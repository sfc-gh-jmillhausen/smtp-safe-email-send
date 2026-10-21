"""Private SQLite ledger plus a process lock shared by send and control commands."""

import fcntl
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime
from zoneinfo import ZoneInfo

from .config import SafetyError, address, digest, private_dir

PENDING = ("PENDING_APPROVAL", "QUEUED", "HELD")


class Store:
    def __init__(self, directory):
        self.directory = private_dir(directory)
        path = directory / "queue.sqlite"
        if path.is_symlink():
            raise SafetyError("Queue cannot be a symlink")
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        path.chmod(0o600)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS setting (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS batch (id TEXT PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL,
          approved_at REAL, approved_digest TEXT);
        CREATE TABLE IF NOT EXISTS message (id TEXT PRIMARY KEY, batch_id TEXT NOT NULL,
          source_id TEXT UNIQUE NOT NULL, recipient TEXT NOT NULL, content_key TEXT UNIQUE NOT NULL,
          state TEXT NOT NULL, retry_at REAL NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
          reason TEXT);
        CREATE TABLE IF NOT EXISTS attempt (id INTEGER PRIMARY KEY, message_id TEXT NOT NULL, at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS suppression (recipient TEXT PRIMARY KEY, reason TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS response_hold (recipient TEXT PRIMARY KEY, reason TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS event (seq INTEGER PRIMARY KEY, key TEXT UNIQUE NOT NULL,
          type TEXT NOT NULL, message_id TEXT, at REAL NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cursor (folder TEXT PRIMARY KEY, validity TEXT NOT NULL, uid INTEGER NOT NULL);
        INSERT OR IGNORE INTO setting VALUES ('enabled','false');
        """)

    def close(self):
        self.db.close()

    @contextmanager
    def lock(self, wait=0):
        path = self.directory / "worker.lock"
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        deadline = time.monotonic() + wait
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    # Senders release the lock between messages, so controls wait briefly for a gap.
                    if time.monotonic() >= deadline:
                        raise SafetyError("Mailbox worker busy; try again in a moment") from None
                    time.sleep(0.2)
            yield
        finally:
            os.close(descriptor)

    def get(self, key, default=None):
        row = self.db.execute("SELECT value FROM setting WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO setting VALUES (?,?)", (key, json.dumps(value)))

    def event(self, key, kind, message_id, now, data):
        self.db.execute("INSERT OR IGNORE INTO event(key,type,message_id,at,data) VALUES (?,?,?,?,?)",
                        (key, kind, message_id, now, json.dumps(data)))

    def pause(self, reason):
        with self.db:
            self.set("enabled", False)
            self.set("pause_reason", reason)

    def add(self, payload):
        batch_id = str(uuid.uuid4())
        try:
            with self.db:
                self.db.execute("INSERT INTO batch(id,payload,digest) VALUES (?,?,?)",
                                (batch_id, json.dumps(payload), digest(payload)))
                for item in payload["messages"]:
                    self.db.execute("INSERT INTO message(id,batch_id,source_id,recipient,content_key,state) VALUES (?,?,?,?,?,?)",
                                    (item["message_id"], batch_id, item["source_id"], item["to"],
                                     item["content_key"], "PENDING_APPROVAL"))
        except sqlite3.IntegrityError:
            raise SafetyError("Source ID or identical content already exists; no duplicate queued") from None
        return batch_id

    def batch(self, batch_id):
        row = self.db.execute("SELECT * FROM batch WHERE id=?", (batch_id,)).fetchone()
        if not row:
            raise SafetyError("Unknown batch")
        payload = json.loads(row["payload"])
        if digest(payload) != row["digest"]:
            raise SafetyError("Batch integrity mismatch")
        return row, payload

    def approve(self, batch_id, expected_digest, config, now):
        row, payload = self.batch(batch_id)
        if row["digest"] != expected_digest or payload["config_hash"] != config.fingerprint():
            raise SafetyError("Preview/configuration changed; prepare and review a new batch")
        if payload["expires_at"] <= now:
            raise SafetyError("Batch expired")
        states = {entry[0] for entry in self.db.execute("SELECT state FROM message WHERE batch_id=?", (batch_id,))}
        if states != {"PENDING_APPROVAL"}:
            raise SafetyError("Only wholly pending batches may be approved")
        if any(self.suppressed(item["to"]) or self.response_held(item["to"]) for item in payload["messages"]):
            raise SafetyError("A recipient is suppressed or has an incoming response awaiting review")
        with self.db:
            self.db.execute("UPDATE batch SET approved_at=?,approved_digest=? WHERE id=?", (now, expected_digest, batch_id))
            self.db.execute("UPDATE message SET state='QUEUED' WHERE batch_id=?", (batch_id,))

    def suppressed(self, recipient):
        return self.db.execute("SELECT 1 FROM suppression WHERE recipient=?", (recipient,)).fetchone() is not None

    def response_held(self, recipient):
        return self.db.execute("SELECT 1 FROM response_hold WHERE recipient=?", (recipient,)).fetchone() is not None

    def suppress(self, recipient, reason):
        recipient = address(recipient)
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO suppression VALUES (?,?)", (recipient, reason))
            self.db.execute("UPDATE message SET state='HELD',reason='suppressed' WHERE recipient=? AND state IN ('QUEUED','PENDING_APPROVAL')", (recipient,))

    def cancel(self, batch_id):
        self.batch(batch_id)
        with self.db:
            self.db.execute("UPDATE message SET state='CANCELLED',reason='user cancelled' WHERE batch_id=? AND state IN ('PENDING_APPROVAL','QUEUED','HELD')", (batch_id,))
            # Never-attempted cancellations free their keys so corrected content can be re-prepared;
            # anything that reached SMTP keeps blocking duplicates.
            self.db.execute("UPDATE message SET source_id=source_id||':cancelled:'||id, content_key=content_key||':cancelled:'||id "
                            "WHERE batch_id=? AND state='CANCELLED' AND attempts=0 AND content_key NOT LIKE '%:cancelled:%'", (batch_id,))

    def recover(self, now):
        rows = self.db.execute("SELECT id FROM message WHERE state='IN_FLIGHT'").fetchall()
        with self.db:
            for row in rows:
                self.db.execute("UPDATE message SET state='UNKNOWN',reason='interrupted submission' WHERE id=?", (row[0],))
                self.event("interrupted:" + row[0], "UNKNOWN", row[0], now, {})
            if rows:
                self.set("enabled", False)
                self.set("pause_reason", "Interrupted submission requires reconciliation")

    def claim(self, config, now, *, monotonic=None, ignore_hours=False):
        monotonic = time.monotonic() if monotonic is None else monotonic
        previous = self.get("clock")
        with self.db:
            if previous and (now < previous[0] or monotonic < previous[1]
                             or abs((now - previous[0]) - (monotonic - previous[1])) > 120):
                self.set("enabled", False)
                self.set("pause_reason", "Clock discontinuity or reboot; review then resume")
            self.set("clock", [now, monotonic])
        if not self.get("enabled", False):
            return None
        local = datetime.fromtimestamp(now, ZoneInfo(config.timezone))
        if not ignore_hours and ((config.weekdays_only and local.weekday() >= 5)
                                 or not config.send_start_hour <= local.hour < config.send_end_hour):
            return None
        recent = self.db.execute("SELECT COUNT(*),MAX(at) FROM attempt WHERE at>?", (now - 86400,)).fetchone()
        if recent[0] >= min(config.max_messages_24h, config.max_recipients_24h):
            return None
        if recent[1] is not None and now - recent[1] < config.min_interval_seconds:
            return None
        # Spacing also counts from the end of the last submission, so slow SMTP sessions cannot bunch sends.
        if now - self.get("last_finished", 0) < config.min_interval_seconds:
            return None
        rows = self.db.execute("SELECT * FROM message WHERE state='QUEUED' AND retry_at<=? ORDER BY rowid", (now,)).fetchall()
        for row in rows:
            batch, payload = self.batch(row["batch_id"])
            item = next(item for item in payload["messages"] if item["message_id"] == row["id"])
            reason = None
            if payload["config_hash"] != config.fingerprint() or batch["approved_digest"] != batch["digest"]:
                reason = "approval/configuration changed"
            elif payload["expires_at"] <= now:
                reason = "expired or stale eligibility"
            elif self.suppressed(row["recipient"]):
                reason = "suppressed"
            elif self.response_held(row["recipient"]):
                reason = "incoming response awaiting review"
            elif item["reply"] and not self.db.execute("SELECT 1 FROM message WHERE id=? AND state='ACCEPTED'", (item["reply"],)).fetchone():
                reason = "reply parent not tracked and accepted"
            elif item["reply"] and now - self.get("last_sync", 0) > 600:
                reason = "IMAP synchronization stale"
            if reason:
                with self.db:
                    self.db.execute("UPDATE message SET state='HELD',reason=? WHERE id=?", (reason, row["id"]))
                continue
            with self.db:
                self.db.execute("UPDATE message SET state='IN_FLIGHT',attempts=attempts+1 WHERE id=?", (row["id"],))
                self.db.execute("INSERT INTO attempt(message_id,at) VALUES (?,?)", (row["id"], now))
            return item
        return None

    def finish(self, item, outcome, now):
        row = self.db.execute("SELECT attempts FROM message WHERE id=?", (item["message_id"],)).fetchone()
        state = outcome.state
        retry_at = 0
        if state == "RETRY":
            if row[0] >= 3:
                state = "FAILED"
            else:
                state = "QUEUED"
                retry_at = now + 600 * (2 ** (row[0] - 1))
        with self.db:
            self.set("last_finished", now)
            self.db.execute("UPDATE message SET state=?,reason=?,retry_at=? WHERE id=?",
                            (state, outcome.reason, retry_at, item["message_id"]))
            self.event(f"attempt:{item['message_id']}:{row[0]}", outcome.state, item["message_id"], now,
                       {"source_id": item["source_id"], "reason": outcome.reason})
            if outcome.pause:
                self.set("enabled", False)
                self.set("pause_reason", outcome.reason)

    def status(self):
        counts = dict(self.db.execute("SELECT state,COUNT(*) FROM message GROUP BY state").fetchall())
        return {"enabled": self.get("enabled", False), "pause_reason": self.get("pause_reason"),
                "messages": counts, "last_sync": self.get("last_sync"), "reader_error": self.get("reader_error"),
                "note": "Local ledger only; ACCEPTED is not delivery or remaining Google quota"}
