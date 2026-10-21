"""One bounded worker tick; service launch is a separate explicit action."""

import json
import os
import plistlib
import subprocess
import sys
import time
from pathlib import Path

from . import imap_sync, transport
from .config import SafetyError, config_path, private_dir, write_private
from .credentials import get_password

LABEL = "local.safe-email-send.worker"


def tick(store, config, now=None, *, ignore_hours=False, budget=50, lock_wait=0):
    """Send approved mail one message at a time, spaced by the configured interval.

    `now` (tests) sends at most one message. `budget` bounds a scheduled tick in
    seconds; None drains until the queue, daily cap or a stop condition is reached.
    The lock is held per message so pause/cancel can act between sends.
    """
    supplied = now is not None
    started = time.monotonic()
    password = session = None
    sent = 0
    result = None
    try:
        while True:
            with store.lock(wait=lock_wait):
                current = now if supplied else time.time()
                store.recover(current)
                if not store.get("enabled", False):
                    result = {"state": "DISABLED", "network": sent > 0}
                    break
                if password is None:
                    try:
                        password = get_password(config)
                    except SafetyError:
                        store.pause("Credential unavailable; review required")
                        raise
                # Sync first: if it fails or is catching up, send nothing more this run.
                if current - store.get("last_sync", 0) >= 300:
                    try:
                        progress = imap_sync.sync(store, config, password, current)
                    except SafetyError:
                        store.pause("IMAP failed; sending paused pending review")
                        raise
                    if not progress["complete"]:
                        result = {"state": "SYNC_CATCHUP", **progress}
                        break
                    current = now if supplied else time.time()
                item = store.claim(config, current, monotonic=time.monotonic(), ignore_hours=ignore_hours)
                if item is None:
                    result = {"state": "IDLE", **store.status()}
                    break
                session = session or transport.Session(config, password)
                outcome = session.send(item)
                store.finish(item, outcome, now if supplied else time.time())
                if outcome.state == "ACCEPTED":
                    sent += 1
                if outcome.state != "ACCEPTED" or supplied:
                    result = {"state": outcome.state, "message_id": item["message_id"], "reason": outcome.reason}
                    break
            wait = config.min_interval_seconds + 0.05
            if budget is not None and time.monotonic() - started + wait > budget:
                result = {"state": "BUDGET_REACHED"}
                break
            time.sleep(wait)
    finally:
        if session is not None:
            session.close()
    return {**result, "sent_this_run": sent}


def service_path():
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def install_service(config):
    if sys.platform != "darwin" or config.credential_backend != "keychain":
        raise SafetyError("Built-in service installation requires macOS and Keychain")
    # Resolve the actual interpreter, not a shell, project cwd or user's aliases.
    program = str(Path(sys.executable).absolute())
    if not Path(program).is_file():
        raise SafetyError("Python interpreter unavailable")
    path = service_path()
    if path.exists():
        raise SafetyError("Service definition already exists; stop/remove it explicitly before replacing")
    document = {"Label": LABEL, "ProgramArguments": [program, "-m", "safe_email_send", "tick", "--service"],
                "StartInterval": 60, "RunAtLoad": False, "ProcessType": "Background"}
    private_dir(path.parent)
    write_private(path, plistlib.dumps(document).decode())
    return {"installed": str(path), "loaded": False, "sending_enabled": False,
            "note": "Definition only. Explicit service-start and resume are separate."}


def service_action(action):
    if sys.platform != "darwin":
        raise SafetyError("LaunchAgent controls require macOS")
    path = service_path()
    if not path.exists():
        raise SafetyError("Service definition not installed")
    command = ["/bin/launchctl", "bootstrap" if action == "start" else "bootout",
               f"gui/{os.getuid()}", str(path)]
    result = subprocess.run(command, capture_output=True, timeout=15, check=False)
    if result.returncode:
        raise SafetyError("launchctl failed; inspect service registration locally")
    return {"service": action, "note": "Queue approval and resume are still required to send"}
