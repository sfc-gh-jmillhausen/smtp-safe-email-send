import socket

import pytest

from safe_email_send.config import Config
from safe_email_send.queue import Store


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Live network is forbidden in the test suite")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    text = tmp_path / "signature.txt"
    html = tmp_path / "signature.html"
    text.write_text("Example Sender\nsender@example.com")
    html.write_text('<div><strong>Example Sender</strong><br><a href="mailto:sender@example.com">sender@example.com</a></div>')
    return Config("sender@example.com", "Example Sender", "Etc/UTC", str(text), str(html),
                  min_interval_seconds=300, max_messages_24h=50, max_recipients_24h=50).validate()


@pytest.fixture
def store(config):
    result = Store(config.state_dir())
    yield result
    result.close()
