import json
import multiprocessing
import ssl
from dataclasses import replace
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

from safe_email_send import credentials, imap_sync, transport, worker
from safe_email_send.cli import main, read_json
from safe_email_send.config import SafetyError, read_env_file, resolve, save_config
from safe_email_send.message import MARKER, prepare_messages
from safe_email_send.queue import Store

NOW = datetime(2026, 10, 21, 10, tzinfo=timezone.utc).timestamp()


def sample(index=1, **kwargs):
    return {"scope": "individual", "messages": [{"to": f"person{index}@example.org", "subject": "Hello",
             "text": "A personal message", "source_id": f"message-{index}", **kwargs}]}


def ready(store, config, index=1, **kwargs):
    payload = prepare_messages(config, sample(index, **kwargs), NOW)
    batch = store.add(payload)
    store.approve(batch, store.batch(batch)[0]["digest"], config, NOW)
    with store.db:
        store.set("enabled", True)
    return batch, payload["messages"][0]


def test_signature_mime_and_unicode(config):
    item = prepare_messages(config, sample(subject="Bonjour Ren\u00e9", text="Hello \u2603"), NOW)["messages"][0]
    mail = BytesParser(policy=policy.default).parsebytes(item["mime"].encode("ascii"))
    assert mail["To"] == "person1@example.org"
    assert mail["Message-ID"] == item["message_id"]
    assert str(mail["Subject"]) == "Bonjour Ren\u00e9"
    assert "Hello \u2603" in mail.get_body(preferencelist=("plain",)).get_content()
    assert item["html"].count(MARKER) == 1
    assert item["text"].count("Example Sender") == 1


@pytest.mark.parametrize("overrides", [{"cc": ["x@example.org"]}, {"bcc": "x@example.org"},
    {"attachment": "a.txt"}, {"to": "x@example.org\r\nBcc: y@example.org"}, {"subject": "Hello\nBcc: injected"},
    {"html": '<img src="https://tracker.example.org/p">'}, {"html": '<div onclick="x()">bad</div>'},
    {"html": '<a href="javascript:alert(1)">bad</a>'}, {"html": '<div class="gmail_signature">old</div>'},
    {"text": "Example Sender\nsender@example.com"}])
def test_reject_unsafe_input(config, overrides):
    with pytest.raises(SafetyError):
        prepare_messages(config, sample(**overrides), NOW)


def test_approval_and_signature_change(store, config):
    payload = prepare_messages(config, sample(), NOW)
    batch = store.add(payload)
    assert store.claim(config, NOW, monotonic=100) is None
    with pytest.raises(SafetyError):
        store.approve(batch, "wrong", config, NOW)
    store.approve(batch, store.batch(batch)[0]["digest"], config, NOW)
    with store.db:
        store.set("enabled", True)
    Path(config.signature_text_path).write_text("New Signature\nsender@example.com")
    assert store.claim(config, NOW + 300, monotonic=400) is None
    assert store.status()["messages"] == {"HELD": 1}


def test_duplicate_and_expired(store, config):
    ready(store, config)
    with pytest.raises(SafetyError):
        store.add(prepare_messages(config, sample(), NOW))
    assert store.claim(config, NOW + 86401) is None
    assert store.status()["messages"] == {"HELD": 1}


def test_campaign_eligibility(store, config):
    batch = {"scope": "campaign", "messages": [sample()["messages"][0], sample(2)["messages"][0]]}
    with pytest.raises(SafetyError):
        prepare_messages(config, batch, NOW)
    batch["eligibility"] = {"source": "Reviewed CRM", "checked_at": "2026-10-21T10:00:00Z",
                            "valid_until": "2026-10-21T11:00:00Z", "allowed_recipients": ["person1@example.org", "person2@example.org"]}
    payload = prepare_messages(config, batch, NOW)
    assert payload["expires_at"] == NOW + 3600
    batch["eligibility"]["allowed_recipients"].pop()
    with pytest.raises(SafetyError):
        prepare_messages(config, batch, NOW)


def test_shared_budget_and_restart(store, config):
    ready(store, config)
    ready(store, config, 2)
    item = store.claim(config, NOW, monotonic=100)
    store.finish(item, transport.Outcome("ACCEPTED", "ok"), NOW)
    other = Store(config.state_dir())
    try:
        assert other.claim(config, NOW + 299, monotonic=399) is None
        assert other.claim(config, NOW + 300, monotonic=400) is not None
        other.recover(NOW + 301)
        assert other.status()["messages"]["UNKNOWN"] == 1
        assert not other.status()["enabled"]
    finally:
        other.close()


def test_daily_limit(store, config):
    limited = replace(config, max_messages_24h=1)
    ready(store, limited)
    ready(store, limited, 2)
    item = store.claim(limited, NOW, monotonic=100)
    store.finish(item, transport.Outcome("ACCEPTED", "ok"), NOW)
    assert store.claim(limited, NOW + 300, monotonic=400) is None


@pytest.mark.parametrize("delta,monotonic", [(-1, 101), (10000, 101), (300, 1)])
def test_clock_changes_pause(store, config, delta, monotonic):
    ready(store, config)
    with store.db:
        store.set("clock", [NOW, 100])
    assert store.claim(config, NOW + delta, monotonic=monotonic) is None
    assert not store.status()["enabled"]


def test_suppression_cancel_and_stale_followup(store, config):
    batch, _ = ready(store, config)
    store.suppress("person1@example.org", "opt out")
    assert store.claim(config, NOW, monotonic=100) is None
    store.cancel(batch)
    assert store.status()["messages"] == {"CANCELLED": 1}
    ready(store, config, 2, in_reply_to="<untracked@example.org>")
    assert store.claim(config, NOW + 300, monotonic=400) is None
    assert store.status()["enabled"]
    assert store.db.execute("SELECT reason FROM message WHERE state='HELD'").fetchone()[0].startswith("reply parent")


class FakeSMTP:
    stage = None
    data_calls = 0
    rcpt_code = 250

    def __init__(self, host, port, timeout):
        assert (host, port, timeout) == ("smtp.gmail.com", 587, 30)
        if self.stage == "connect":
            raise OSError("secret provider detail")

    def ehlo(self):
        pass

    def starttls(self, context):
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        if self.stage == "tls":
            raise ssl.SSLError("bad certificate")

    def login(self, username, password):
        if self.stage == "auth":
            import smtplib
            raise smtplib.SMTPAuthenticationError(535, b"secret response")

    def mail(self, sender):
        assert sender == "sender@example.com"
        return 250, b"ok"

    def rcpt(self, recipient):
        return self.rcpt_code, b"ok"

    def data(self, payload):
        self.__class__.data_calls += 1
        if self.stage == "data":
            raise OSError("uncertain")
        return 250, b"accepted"

    def quit(self):
        if self.stage == "quit":
            raise OSError("quit failed")

    def close(self):
        pass


@pytest.mark.parametrize("stage,expected", [(None, "ACCEPTED"), ("connect", "RETRY"), ("tls", "FAILED"),
                                            ("auth", "FAILED"), ("data", "UNKNOWN"), ("quit", "ACCEPTED")])
def test_smtp_failure_states(config, stage, expected, monkeypatch):
    monkeypatch.setattr(FakeSMTP, "stage", stage)
    item = prepare_messages(config, sample(), NOW)["messages"][0]
    outcome = transport.submit(config, "abcdefghijklmnop", item, FakeSMTP)
    assert outcome.state == expected
    assert "secret" not in outcome.reason


def test_refused_recipient_never_sends(config, monkeypatch):
    monkeypatch.setattr(FakeSMTP, "rcpt_code", 550)
    monkeypatch.setattr(FakeSMTP, "data_calls", 0)
    item = prepare_messages(config, sample(), NOW)["messages"][0]
    assert transport.submit(config, "abcdefghijklmnop", item, FakeSMTP).state == "FAILED"
    assert FakeSMTP.data_calls == 0


def reply(item, sender="person1@example.org", extra="", incoming="incoming"):
    return (f"Message-ID: <{incoming}@example.org>\r\nFrom: {sender}\r\nTo: sender@example.com\r\n"
            f"In-Reply-To: {item['message_id']}\r\n{extra}\r\n").encode()


def test_imap_reply_dedup_holds_related(store, config):
    _, item = ready(store, config)
    store.claim(config, NOW)
    store.finish(item, transport.Outcome("ACCEPTED", "ok"), NOW)
    ready(store, config, 2, to="person1@example.org", text="Different next message")
    with store.db:
        imap_sync.observe(store, config, reply(item), NOW + 30)
        imap_sync.observe(store, config, reply(item), NOW + 31)
    assert store.db.execute("SELECT COUNT(*) FROM event WHERE type='REPLY_CANDIDATE'").fetchone()[0] == 1
    assert store.status()["messages"]["HELD"] == 1


@pytest.mark.parametrize("sender,extra,kind", [("other@example.org", "", "REPLY_REVIEW"),
    ("person1@example.org", "Auto-Submitted: auto-replied\r\n", "AUTO_REPLY"),
    ("mailer-daemon@example.org", 'Content-Type: multipart/report; report-type="delivery-status"\r\n', "BOUNCE_CANDIDATE")])
def test_imap_classification(store, config, sender, extra, kind):
    _, item = ready(store, config)
    store.claim(config, NOW)
    store.finish(item, transport.Outcome("ACCEPTED", "ok"), NOW)
    with store.db:
        imap_sync.observe(store, config, reply(item, sender, extra), NOW + 30)
    assert store.db.execute("SELECT COUNT(*) FROM event WHERE type=?", (kind,)).fetchone()[0] == 1


class FakeIMAP:
    raw = b""
    validity = b"10"
    next_uid = b"3"

    def __init__(self, host, port, ssl_context, timeout):
        assert (host, port, timeout) == ("imap.gmail.com", 993, 30)
        assert ssl_context.verify_mode == ssl.CERT_REQUIRED and ssl_context.check_hostname

    def login(self, username, password):
        return "OK", [b"ok"]

    def list(self):
        return "OK", [b'(\\HasNoChildren \\All) "/" "[Gmail]/Tous les messages"']

    def select(self, folder, readonly):
        assert readonly is True
        assert "Tous les messages" in folder
        return "OK", [b"2"]

    def response(self, key):
        return key, [self.validity if key == "UIDVALIDITY" else self.next_uid]

    def uid(self, command, *args):
        if command == "SEARCH":
            return "OK", [b"1 2"]
        assert command == "FETCH" and "BODY.PEEK" in args[1]
        return "OK", [(b"1 (UID 1 BODY[HEADER] {200}", self.raw), b")"]

    def logout(self):
        return "BYE", [b"bye"]


def test_sync_cursor_and_uidvalidity(store, config, monkeypatch):
    _, item = ready(store, config)
    store.claim(config, NOW)
    store.finish(item, transport.Outcome("ACCEPTED", "ok"), NOW)
    monkeypatch.setattr(FakeIMAP, "raw", reply(item))
    assert imap_sync.sync(store, config, "abcdefghijklmnop", NOW + 30, FakeIMAP)["complete"]
    assert store.db.execute("SELECT uid FROM cursor").fetchone()[0] == 2
    monkeypatch.setattr(FakeIMAP, "validity", b"20")
    imap_sync.sync(store, config, "abcdefghijklmnop", NOW + 60, FakeIMAP)
    assert store.db.execute("SELECT validity FROM cursor").fetchone()[0] == "20"
    assert store.db.execute("SELECT COUNT(*) FROM event WHERE type='REPLY_CANDIDATE'").fetchone()[0] == 1


def test_config_env_no_secrets(config, tmp_path, monkeypatch):
    save_config(config)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("SAFE_EMAIL_ADDRESS=evil@example.org")
    assert resolve(environ={}).address == config.address
    with pytest.raises(SafetyError):
        resolve(environ={"SAFE_EMAIL_MAX_MESSAGES_24H": "2000"})
    file = tmp_path / "explicit.env"
    file.write_text("SAFE_EMAIL_APP_PASSWORD=abcdefghijklmnop")
    with pytest.raises(SafetyError):
        read_env_file(file)
    assert "abcdefghijklmnop" not in (tmp_path / ".config/safe-email-send/config.json").read_text()


def test_explicit_credentials_no_fallback(config, monkeypatch):
    monkeypatch.delenv("SAFE_EMAIL_APP_PASSWORD", raising=False)
    with pytest.raises(SafetyError):
        credentials.get_password(replace(config, credential_backend="env"))
    monkeypatch.setenv("SAFE_EMAIL_APP_PASSWORD", "abcdefghijklmnop")
    assert credentials.get_password(replace(config, credential_backend="env")) == "abcdefghijklmnop"
    def locked():
        raise RuntimeError("secret should not escape")
    monkeypatch.setattr(credentials, "mac_keychain", locked)
    with pytest.raises(SafetyError, match="unavailable"):
        credentials.get_password(config)


def test_disabled_tick_no_network_or_credentials(store, config, monkeypatch):
    def forbidden(*args):
        raise AssertionError("Disabled tick accessed credential")
    monkeypatch.setattr(worker, "get_password", forbidden)
    assert worker.tick(store, config, NOW)["network"] is False


def lock_child(directory, pipe):
    instance = Store(Path(directory))
    try:
        with instance.lock():
            pipe.send("acquired")
    except SafetyError:
        pipe.send("blocked")
    finally:
        instance.close()


def test_cross_process_lock(store):
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    with store.lock():
        process = context.Process(target=lock_child, args=(str(store.directory), child))
        process.start()
        assert parent.poll(10)
        assert parent.recv() == "blocked"
        process.join(10)
        assert process.exitcode == 0


def test_cli_offline_flow(config, tmp_path, capsys):
    save_config(config)
    file = tmp_path / "input.json"
    file.write_text(json.dumps(sample()))
    main(["prepare", str(file)])
    output = json.loads(capsys.readouterr().out)
    main(["preview", output["batch_id"]])
    preview = json.loads(capsys.readouterr().out)
    assert preview["messages"][0]["html"].count(MARKER) == 1
    main(["approve", output["batch_id"], "--digest", output["digest"], "--confirm", "APPROVE"])
    assert not json.loads(capsys.readouterr().out)["sending_enabled"]
    main(["tick"])
    assert json.loads(capsys.readouterr().out)["state"] == "DISABLED"


def test_two_profiles_no_identity_leak(config, tmp_path):
    second_text, second_html = tmp_path / "second.txt", tmp_path / "second.html"
    second_text.write_text("Other User\nother@example.net")
    second_html.write_text("<p>Other User<br>other@example.net</p>")
    other = replace(config, address="other@example.net", display_name="Other User", timezone="Europe/London",
                    signature_text_path=str(second_text), signature_html_path=str(second_html)).validate()
    first = prepare_messages(config, sample(), NOW)
    second = prepare_messages(other, sample(), NOW)
    assert "Other User" not in first["messages"][0]["text"]
    assert "Example Sender" not in second["messages"][0]["text"]
    assert config.state_dir() != other.state_dir()


def test_duplicate_json_fields(tmp_path):
    path = tmp_path / "input.json"
    path.write_text('{"to":"one@example.org","to":"two@example.org"}')
    with pytest.raises(SafetyError):
        read_json(path)


def test_launchagent_is_disabled_no_secrets(config, monkeypatch):
    import plistlib
    monkeypatch.setattr(worker.sys, "platform", "darwin")
    result = worker.install_service(config)
    assert result["loaded"] is False
    document = plistlib.loads(Path(result["installed"]).read_bytes())
    assert document["RunAtLoad"] is False
    assert "EnvironmentVariables" not in document
    assert document["ProgramArguments"][-1] == "--service"

def test_response_hold_blocks_new_approval_until_release(store, config, tmp_path, capsys):
    _, item = ready(store, config)
    store.claim(config, NOW, monotonic=100)
    store.finish(item, transport.Outcome("ACCEPTED", "ok"), NOW)
    with store.db:
        imap_sync.observe(store, config, reply(item), NOW + 30)
    payload = prepare_messages(config, sample(3, to="person1@example.org", text="New note"), NOW + 60)
    batch = store.add(payload)
    with pytest.raises(SafetyError):
        store.approve(batch, store.batch(batch)[0]["digest"], config, NOW + 60)
    save_config(config)
    store.close()
    main(["release-response-hold", "person1@example.org", "--confirm", "RELEASE"])
    assert json.loads(capsys.readouterr().out)["released"] == "person1@example.org"
    reopened = Store(config.state_dir())
    try:
        assert not reopened.response_held("person1@example.org")
    finally:
        reopened.close()


def test_signature_logo_allowed_only_in_signature(config):
    Path(config.signature_html_path).write_text(
        '<div><img src="https://cdn.example.org/logo.png" alt="Logo"><br>sender@example.com</div>')
    item = prepare_messages(config, sample(), NOW)["messages"][0]
    assert "https://cdn.example.org/logo.png" in item["html"]
    Path(config.signature_html_path).write_text('<div><img src="https://cdn.example.org/p.png?id=1">sender@example.com</div>')
    with pytest.raises(SafetyError):
        prepare_messages(config, sample(), NOW)


def test_spacing_counts_from_finish(store, config):
    ready(store, config)
    ready(store, config, 2)
    item = store.claim(config, NOW, monotonic=100)
    store.finish(item, transport.Outcome("ACCEPTED", "ok"), NOW + 200)
    assert store.claim(config, NOW + 300, monotonic=400) is None
    assert store.claim(config, NOW + 500, monotonic=600) is not None


def test_defaults_and_ceilings(config):
    base = replace(config, min_interval_seconds=2, max_messages_24h=1000, max_recipients_24h=1000).validate()
    assert (base.send_start_hour, base.send_end_hour, base.weekdays_only) == (8, 17, True)
    for bad in [{"max_messages_24h": 1001}, {"min_interval_seconds": 0}, {"send_start_hour": 17, "send_end_hour": 8}]:
        with pytest.raises(SafetyError):
            replace(base, **bad).validate()
    assert resolve(environ={"SAFE_EMAIL_WEEKDAYS_ONLY": "false"}, saved=False, values={
        "SAFE_EMAIL_ADDRESS": config.address, "SAFE_EMAIL_DISPLAY_NAME": "Example Sender", "SAFE_EMAIL_TIMEZONE": "Etc/UTC",
        "SAFE_EMAIL_SIGNATURE_TEXT_PATH": config.signature_text_path,
        "SAFE_EMAIL_SIGNATURE_HTML_PATH": config.signature_html_path}).weekdays_only is False


def test_hours_window_and_ad_hoc_override(store, config):
    early = datetime(2026, 10, 21, 7, 30, tzinfo=timezone.utc).timestamp()
    ready(store, config)
    assert store.claim(config, early, monotonic=100) is None
    assert store.claim(config, early + 1, monotonic=101, ignore_hours=True) is not None


class FakeClock:
    def __init__(self, start):
        self.wall, self.mono, self.sleeps = start, 1000.0, []

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.wall += seconds
        self.mono += seconds


class FakeSession:
    logins = 0
    sent = []

    def __init__(self, config, password, factory=None):
        FakeSession.logins += 1

    def send(self, item):
        FakeSession.sent.append(item["to"])
        return transport.Outcome("ACCEPTED", "ok")

    def close(self):
        pass


def drain_setup(store, config, monkeypatch, count=3, **overrides):
    fast = replace(config, min_interval_seconds=2, **overrides).validate()
    for index in range(1, count + 1):
        ready(store, fast, index)
    clock = FakeClock(NOW)
    monkeypatch.setattr(worker, "time", clock)
    monkeypatch.setattr(worker, "get_password", lambda config: "abcdefghijklmnop")
    def fake_sync(store, config, password, now):
        with store.db:
            store.set("last_sync", now)
        return {"observed": 0, "complete": True}
    monkeypatch.setattr(worker.imap_sync, "sync", fake_sync)
    monkeypatch.setattr(worker.transport, "Session", FakeSession)
    monkeypatch.setattr(FakeSession, "logins", 0)
    monkeypatch.setattr(FakeSession, "sent", [])
    return fast, clock


def test_drain_spaces_sends_and_reuses_one_login(store, config, monkeypatch):
    fast, clock = drain_setup(store, config, monkeypatch)
    result = worker.tick(store, fast, budget=None)
    assert result["sent_this_run"] == 3 and result["state"] == "IDLE"
    assert FakeSession.logins == 1
    assert all(abs(pause - 2.05) < 1e-9 for pause in clock.sleeps)


def test_budget_bounds_scheduled_tick(store, config, monkeypatch):
    fast, _ = drain_setup(store, config, monkeypatch, count=5)
    result = worker.tick(store, fast, budget=5)
    # Sends at t=0, 2.05 and 4.1s; a fourth would start past the 5s budget.
    assert result["state"] == "BUDGET_REACHED" and result["sent_this_run"] == 3


def test_drain_respects_daily_cap(store, config, monkeypatch):
    capped, _ = drain_setup(store, config, monkeypatch, max_messages_24h=2)
    result = worker.tick(store, capped, budget=None)
    assert result["state"] == "IDLE" and result["sent_this_run"] == 2
    assert store.status()["messages"] == {"ACCEPTED": 2, "QUEUED": 1}


def test_session_reuses_connection_and_reconnects_on_stale(config, monkeypatch):
    connections = []

    class Counting(FakeSMTP):
        drop_next = False

        def __init__(self, host, port, timeout):
            super().__init__(host, port, timeout)
            connections.append(self)

        def mail(self, sender):
            if Counting.drop_next:
                Counting.drop_next = False
                raise OSError("stale")
            return super().mail(sender)

    monkeypatch.setattr(FakeSMTP, "stage", None)
    items = [prepare_messages(config, sample(index), NOW)["messages"][0] for index in (1, 2, 3)]
    session = transport.Session(config, "abcdefghijklmnop", Counting)
    assert session.send(items[0]).state == "ACCEPTED"
    assert session.send(items[1]).state == "ACCEPTED"
    assert len(connections) == 1
    Counting.drop_next = True
    assert session.send(items[2]).state == "ACCEPTED"
    assert len(connections) == 2
    session.close()


def test_send_now_cli_requires_confirmation(config):
    save_config(config)
    with pytest.raises(SystemExit):
        main(["send-now"])


def test_cancel_unsent_allows_reprepare_but_sent_blocks(store, config):
    batch, _ = ready(store, config)
    store.cancel(batch)
    again = store.add(prepare_messages(config, sample(), NOW))
    store.approve(again, store.batch(again)[0]["digest"], config, NOW)
    item = store.claim(config, NOW, monotonic=100)
    store.finish(item, transport.Outcome("ACCEPTED", "ok"), NOW)
    with pytest.raises(SafetyError):
        store.add(prepare_messages(config, sample(), NOW))
