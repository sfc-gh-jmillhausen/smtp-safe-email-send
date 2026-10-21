"""Bounded Gmail IMAP observation. No STORE, EXPUNGE or read-state changes."""

import imaplib
import re
import ssl
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses

from .config import SafetyError, digest
from .message import ID_PATTERN

HEADER_FIELDS = "MESSAGE-ID FROM TO CC IN-REPLY-TO REFERENCES AUTO-SUBMITTED PRECEDENCE CONTENT-TYPE X-AUTOREPLY X-AUTORESPOND"


def ok(result, operation):
    status, data = result
    if status != "OK":
        raise SafetyError(f"IMAP {operation} failed; no policy workaround attempted")
    return data


def number(server, name):
    _, values = server.response(name)
    if not values or not values[0] or not re.fullmatch(rb"[0-9]+", values[0]):
        raise SafetyError(f"IMAP missing {name}")
    return int(values[0])


def folders(server):
    result = []
    for entry in ok(server.list(), "LIST"):
        if not isinstance(entry, bytes):
            raise SafetyError("Unsupported IMAP literal mailbox name; review configuration")
        match = re.fullmatch(rb'\(([^)]*)\) (?:NIL|"(?:[^"\\]|\\.)*") (.+)', entry)
        if not match:
            raise SafetyError("Unrecognized mailbox LIST response")
        attributes = match[1].lower().split()
        name = match[2].decode("ascii")
        if b"\\noselect" in attributes:
            continue
        if name.strip('"').upper() == "INBOX" or any(flag in attributes for flag in [b"\\all", b"\\allmail", b"\\junk"]):
            result.append(name)
    if not result:
        raise SafetyError("No readable Inbox/All Mail folders discovered")
    return sorted(set(result))


def header_addresses(message, field):
    return {addr.lower() for _, addr in getaddresses([str(value) for value in message.get_all(field, [])]) if addr}


def observe(store, config, raw, now, *, body=None):
    header = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    identifiers = ID_PATTERN.findall(str(header.get("Message-ID", "")))
    if len(identifiers) != 1 or header.defects:
        return
    incoming_id = identifiers[0]
    if store.db.execute("SELECT 1 FROM event WHERE key LIKE ?", ("imap:" + digest(incoming_id) + ":%",)).fetchone():
        return
    senders = header_addresses(header, "From")
    if config.address in senders:
        # Sent-mail appearance is useful evidence, but not an automatic UNKNOWN retry decision.
        tracked = store.db.execute("SELECT id,recipient FROM message WHERE id=?", (incoming_id,)).fetchone()
        if tracked and tracked["recipient"] in header_addresses(header, "To"):
            store.event("sent-observed:" + incoming_id, "SENT_OBSERVED", incoming_id, now, {})
        return
    refs = ID_PATTERN.findall(str(header.get("In-Reply-To", "")) + " " + str(header.get("References", "")))
    dsn = header.get_content_type() == "multipart/report" and header.get_param("report-type") == "delivery-status"
    if dsn and body:
        parsed = BytesParser(policy=policy.default).parsebytes(body)
        # Some DSNs include the original headers as a nested rfc822 message.
        for part in parsed.walk():
            if part is not parsed:
                refs.extend(ID_PATTERN.findall(str(part.get("Message-ID", ""))))
    candidates = []
    for reference in reversed(list(dict.fromkeys(refs))):
        row = store.db.execute("SELECT * FROM message WHERE id=? AND state IN ('ACCEPTED','UNKNOWN','IN_FLIGHT')", (reference,)).fetchone()
        if row:
            candidates.append(row)
    if not candidates:
        return
    target = candidates[0]
    addressed_to_us = config.address in (header_addresses(header, "To") | header_addresses(header, "Cc"))
    auto = (str(header.get("Auto-Submitted", "no")).lower() != "no"
            or header.get("X-Autoreply") is not None or header.get("X-Autorespond") is not None
            or str(header.get("Precedence", "")).lower() in {"bulk", "list", "junk"})
    exact = len(senders) == 1 and target["recipient"] in senders and addressed_to_us
    if dsn:
        kind = "BOUNCE_CANDIDATE"
    elif not exact or len({candidate["recipient"] for candidate in candidates}) > 1:
        kind = "REPLY_REVIEW"
    else:
        kind = "AUTO_REPLY" if auto else "REPLY_CANDIDATE"
    # Headers can be spoofed. A matched event holds outbound work rather than
    # performing irreversible suppression or asserting a verified human identity.
    store.event("imap:" + digest(incoming_id) + ":" + kind, kind, target["id"], now,
                {"incoming_message_id": incoming_id, "source_id": target["source_id"],
                 "recipient": target["recipient"], "identity_verified": False})
    store.db.execute("INSERT OR IGNORE INTO response_hold VALUES (?,?)", (target["recipient"], kind))
    store.db.execute("UPDATE message SET state='HELD',reason=? WHERE recipient=? AND state IN ('QUEUED','PENDING_APPROVAL')",
                     ("Incoming response requires review: " + kind, target["recipient"]))


def delivery_report(server, config, raw, uid):
    header = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    if not (header.get_content_type() == "multipart/report" and header.get_param("report-type") == "delivery-status"
            and config.address in header_addresses(header, "To")):
        return None
    # Bounded, read-only body fetch so a DSN can be matched to the original Message-ID.
    response = ok(server.uid("FETCH", str(uid), "(UID BODY.PEEK[]<0.131072>)"), "bounded report fetch")
    bodies = [entry[1] for entry in response if isinstance(entry, tuple)]
    if len(bodies) != 1 or not isinstance(bodies[0], bytes) or len(bodies[0]) >= 131072:
        raise SafetyError("Malformed/oversized delivery report; cursor not advanced")
    return bodies[0]


def sync(store, config, password, now, factory=imaplib.IMAP4_SSL):
    earliest = store.db.execute("SELECT MIN(at) FROM attempt").fetchone()[0]
    if earliest is None:
        with store.db:
            store.set("last_sync", now)
            store.set("reader_error", None)
        return {"observed": 0, "complete": True, "note": "No tracked sends; mailbox not scanned"}
    server = None
    processed = 0
    complete = True
    try:
        server = factory("imap.gmail.com", 993, ssl_context=ssl.create_default_context(), timeout=30)
        ok(server.login(config.address, password), "login")
        selected = folders(server)
        if len(selected) > 5:
            raise SafetyError("Too many special-use folders; review required")
        for folder in selected:
            ok(server.select(folder, readonly=True), "read-only selection")
            validity = str(number(server, "UIDVALIDITY"))
            uidnext = number(server, "UIDNEXT")
            cursor = store.db.execute("SELECT * FROM cursor WHERE folder=?", (folder,)).fetchone()
            if cursor is None or cursor["validity"] != validity:
                cutoff = datetime.fromtimestamp(max(earliest - 86400, now - 30 * 86400), timezone.utc)
                # English month abbreviations are mandated by IMAP regardless of OS locale.
                months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
                since = f"{cutoff.day:02d}-{months[cutoff.month - 1]}-{cutoff.year}"
                data = ok(server.uid("SEARCH", None, "SINCE", since), "initial bounded-date search")
                if len(data) != 1 or not isinstance(data[0], bytes) or len(data[0]) > 100000:
                    raise SafetyError("IMAP initial result too large; explicit mailbox review required")
                numbers = [int(value) for value in data[0].split()]
                cursor_uid = min(numbers) - 1 if numbers else uidnext - 1
                with store.db:
                    store.db.execute("INSERT OR REPLACE INTO cursor VALUES (?,?,?)", (folder, validity, cursor_uid))
            else:
                cursor_uid = cursor["uid"]
            if cursor_uid >= uidnext:
                raise SafetyError("IMAP UID cursor invalid; review required")
            upper = min(uidnext - 1, cursor_uid + 100)
            if upper > cursor_uid:
                response = ok(server.uid("FETCH", f"{cursor_uid + 1}:{upper}",
                                         f"(UID BODY.PEEK[HEADER.FIELDS ({HEADER_FIELDS})]<0.16384>)"), "header fetch")
                with store.db:
                    for entry in response:
                        if not isinstance(entry, tuple):
                            continue
                        metadata, raw = entry
                        uid = re.search(rb"\bUID (\d+)\b", metadata)
                        if not uid or not isinstance(raw, bytes) or len(raw) >= 16384:
                            raise SafetyError("IMAP malformed/oversized header; cursor not advanced")
                        actual_uid = int(uid[1])
                        if not cursor_uid < actual_uid <= upper:
                            raise SafetyError("IMAP returned an unexpected UID")
                        observe(store, config, raw, now, body=delivery_report(server, config, raw, actual_uid))
                        processed += 1
                    store.db.execute("UPDATE cursor SET uid=? WHERE folder=?", (upper, folder))
            if upper < uidnext - 1:
                complete = False
        with store.db:
            if complete:
                store.set("last_sync", now)
            store.set("reader_error", None)
        return {"observed": processed, "complete": complete}
    except Exception:
        with store.db:
            store.set("reader_error", "IMAP access/sync failed; no mailbox modifications made")
        raise SafetyError("IMAP access/sync failed; check policy/credentials or oversized mailbox results") from None
    finally:
        if server is not None:
            try:
                server.logout()
            except Exception:
                pass


def check_login(config, password, factory=imaplib.IMAP4_SSL):
    server = factory("imap.gmail.com", 993, ssl_context=ssl.create_default_context(), timeout=30)
    try:
        ok(server.login(config.address, password), "login")
        for folder in folders(server):
            ok(server.select(folder, readonly=True), "read-only selection")
            number(server, "UIDVALIDITY")
    finally:
        server.logout()