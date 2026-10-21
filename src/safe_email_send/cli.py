"""CLI entry point. No hidden network operations in setup/prepare/preview/status."""

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path

from . import __version__, imap_sync, transport, worker
from .config import ENV_FIELDS, SafetyError, read_env_file, resolve, safe_text, save_config
from .credentials import get_password, store_password
from .message import prepare_messages
from .queue import Store


def parser():
    root = argparse.ArgumentParser(description="Approval-gated SMTP queue and read-only IMAP observer")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("setup", help="Save nonsecret configuration; no network or activation")
    setup.add_argument("--env-file", type=Path)
    commands.add_parser("credential-set", help="User-run hidden prompt; save in macOS Keychain only")
    doctor = commands.add_parser("doctor", help="Offline validation; --connect explicitly tests SMTP/IMAP login")
    doctor.add_argument("--connect", action="store_true")
    prepare = commands.add_parser("prepare", help="Prepare unsigned JSON batch with configured signature")
    prepare.add_argument("file", type=Path)
    for name in ["preview", "cancel"]:
        commands.add_parser(name).add_argument("batch_id")
    approve = commands.add_parser("approve")
    approve.add_argument("batch_id")
    approve.add_argument("--digest", required=True)
    approve.add_argument("--confirm", required=True, choices=["APPROVE"])
    commands.add_parser("status")
    commands.add_parser("pause")
    resume = commands.add_parser("resume")
    resume.add_argument("--confirm", required=True, choices=["RESUME"])
    suppress = commands.add_parser("suppress")
    suppress.add_argument("address")
    suppress.add_argument("--reason", required=True)
    release = commands.add_parser("release-response-hold", help="After reviewing a reply, allow future mail to that person")
    release.add_argument("address")
    release.add_argument("--confirm", required=True, choices=["RELEASE"])
    imported = commands.add_parser("suppression-import")
    imported.add_argument("file", type=Path)
    commands.add_parser("sync", help="Explicit read-only IMAP synchronization")
    tick = commands.add_parser("tick", help="One bounded worker run; only approved/enabled mail can send")
    tick.add_argument("--service", action="store_true", help=argparse.SUPPRESS)
    send_now = commands.add_parser("send-now", help="Ad hoc: send approved queued mail now, ignoring send hours")
    send_now.add_argument("--confirm", required=True, choices=["SEND"])
    events = commands.add_parser("events")
    events.add_argument("--after", type=int, default=0)
    for name, confirmation in [("service-install", "INSTALL"), ("service-start", "START"), ("service-stop", "STOP")]:
        command = commands.add_parser(name)
        command.add_argument("--confirm", required=True, choices=[confirmation])
    return root


def read_json(path):
    if not path.is_file() or path.stat().st_size > 2_000_000:
        raise SafetyError("Input must be a JSON file <=2 MB")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SafetyError("Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique_pairs)


def configure(args):
    if args.env_file:
        values = read_env_file(args.env_file)
    else:
        values = {}
        prompts = {"ADDRESS": "Mailbox email", "DISPLAY_NAME": "Sender display name", "TIMEZONE": "IANA timezone",
                   "SIGNATURE_TEXT_PATH": "Absolute text signature path", "SIGNATURE_HTML_PATH": "Absolute HTML signature path"}
        for field, label in prompts.items():
            values["SAFE_EMAIL_" + field] = input(label + ": ").strip()
    config = resolve(values, saved=False)
    # Identity changes must not leave an old mailbox's service silently enabled.
    try:
        old = resolve(environ={})
    except (SafetyError, FileNotFoundError):
        old = None
    if old:
        previous = Store(old.state_dir())
        try:
            with previous.lock():
                previous.pause("Configuration changed; review then resume")
        finally:
            previous.close()
    save_config(config)
    current = Store(config.state_dir())
    try:
        with current.lock():
            current.pause("Setup complete; disabled until explicit resume")
    finally:
        current.close()
    return {"configured": True, "sending_enabled": False, "credential_stored": False}


def run(args):
    now = time.time()
    if args.command == "setup":
        return configure(args)
    # Background services use only persisted config, never incidental shell overrides.
    config = resolve(environ={} if getattr(args, "service", False) else None)
    if args.command == "credential-set":
        if not sys.stdin.isatty():
            raise SafetyError("Run credential-set yourself in an interactive terminal")
        password = getpass.getpass("New Gmail app password (hidden): ")
        store_password(config, password)
        return {"stored": "macOS Keychain", "authenticated": False, "sent": 0}
    if args.command == "doctor":
        if args.connect:
            password = get_password(config)
            try:
                transport.check_login(config, password)
                imap_sync.check_login(config, password)
            except Exception:
                raise SafetyError("SMTP/IMAP diagnostic failed; verify access policy and credentials") from None
        return {"configuration": "valid", "smtp_imap_login_tested": args.connect, "sent": 0}
    store = Store(config.state_dir())
    try:
        if args.command == "tick":
            return worker.tick(store, config)
        if args.command == "send-now":
            # Spacing, daily caps, approvals and reply holds still apply; only the hours window is skipped.
            return worker.tick(store, config, ignore_hours=True, budget=None, lock_wait=30)
        with store.lock(wait=30):
            if args.command == "prepare":
                payload = prepare_messages(config, read_json(args.file), now)
                batch_id = store.add(payload)
                return {"batch_id": batch_id, "digest": store.batch(batch_id)[0]["digest"], "state": "PENDING_APPROVAL"}
            if args.command == "preview":
                row, payload = store.batch(args.batch_id)
                return {"batch_id": args.batch_id, "digest": row["digest"], "scope": payload["scope"],
                        "expires_at": payload["expires_at"], "eligibility": payload["eligibility"],
                        "config_matches": payload["config_hash"] == config.fingerprint(),
                        "policy": {"interval_seconds": config.min_interval_seconds, "max_24h": min(config.max_messages_24h, config.max_recipients_24h),
                                   "timezone": config.timezone,
                                   "hours": f"{'Mon-Fri' if config.weekdays_only else 'Every day'} "
                                            f"{config.send_start_hour:02d}:00-{config.send_end_hour:02d}:00"},
                        "messages": [{key: value for key, value in item.items() if key != "mime"} for item in payload["messages"]]}
            if args.command == "approve":
                store.approve(args.batch_id, args.digest, config, now)
                return {"approved": args.batch_id, "sending_enabled": store.get("enabled", False)}
            if args.command == "pause":
                store.pause("User paused sending")
            elif args.command == "resume":
                store.recover(now)
                if store.db.execute("SELECT 1 FROM message WHERE state='UNKNOWN'").fetchone():
                    raise SafetyError("UNKNOWN submissions block resume; reconcile before any further sending")
                get_password(config)
                with store.db:
                    store.set("enabled", True)
                    store.set("pause_reason", None)
                    store.set("clock", [now, time.monotonic()])
            elif args.command == "cancel":
                store.cancel(args.batch_id)
            elif args.command == "suppress":
                store.suppress(args.address, safe_text(args.reason, "suppression reason", 500))
            elif args.command == "release-response-hold":
                from .config import address
                with store.db:
                    store.db.execute("DELETE FROM response_hold WHERE recipient=?", (address(args.address),))
                # Previously held messages stay HELD; prepare and approve fresh content after reading the reply.
                return {"released": address(args.address), "held_messages_requeued": 0}
            elif args.command == "suppression-import":
                data = read_json(args.file)
                if not isinstance(data, dict) or set(data) != {"source", "recipients"} or not isinstance(data["recipients"], list):
                    raise SafetyError("Suppression import requires source and recipients list")
                from .config import address
                reason = safe_text(data["source"], "suppression source", 500)
                recipients = [address(value) for value in data["recipients"]]
                for recipient in recipients:
                    store.suppress(recipient, reason)
            elif args.command == "sync":
                return imap_sync.sync(store, config, get_password(config), now)
            elif args.command == "events":
                rows = store.db.execute("SELECT * FROM event WHERE seq>? ORDER BY seq LIMIT 200", (args.after,)).fetchall()
                return {"events": [{**dict(row), "data": json.loads(row["data"])} for row in rows],
                        "next_after": rows[-1]["seq"] if rows else args.after}
            elif args.command == "service-install":
                store.pause("Service installed disabled; explicit resume required")
                return worker.install_service(config)
            elif args.command in {"service-start", "service-stop"}:
                if args.command == "service-stop":
                    store.pause("Service stopped")
                return worker.service_action(args.command.split("-")[1])
            return store.status()
    finally:
        store.close()


def main(argv=None):
    # Includes SQLite journals and any runtime artifacts created by dependencies.
    os.umask(0o077)
    args = parser().parse_args(argv)
    try:
        print(json.dumps(run(args), indent=2, ensure_ascii=True))
    except SafetyError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        raise SystemExit(2)
    except Exception:
        # Raw server, file and Keychain exceptions may contain confidential values.
        print(json.dumps({"error": "Operation failed; inspect configuration/input locally. No automatic retry."}), file=sys.stderr)
        raise SystemExit(2)
