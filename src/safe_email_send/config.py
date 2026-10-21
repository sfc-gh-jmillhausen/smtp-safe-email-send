"""Explicit nonsecret configuration; never discover .env in a working directory."""

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from zoneinfo import ZoneInfo


class SafetyError(Exception):
    """A safe, user-facing diagnostic (no provider responses or credentials)."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def address(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}", value
    ) or len(value) > 254 or ".." in value:
        raise SafetyError("Expected a single ASCII email address without display name or whitespace")
    return value.lower()


def safe_text(value, name, maximum=1000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise SafetyError(f"Invalid {name}")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SafetyError(f"Control characters are not allowed in {name}")
    return value


def private_dir(path):
    if path.is_symlink():
        raise SafetyError("Private directory cannot be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def write_private(path, text):
    private_dir(path.parent)
    if path.is_symlink():
        raise SafetyError("Private file cannot be a symlink")
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def config_path():
    return Path.home() / ".config" / "safe-email-send" / "config.json"


@dataclass(frozen=True)
class Config:
    address: str
    display_name: str
    timezone: str
    signature_text_path: str
    signature_html_path: str
    provider: str = "gmail"
    credential_backend: str = "keychain"
    min_interval_seconds: int = 2
    max_messages_24h: int = 1000
    max_recipients_24h: int = 1000
    send_start_hour: int = 8
    send_end_hour: int = 17
    weekdays_only: bool = True

    def validate(self):
        if address(self.address) != self.address:
            raise SafetyError("Use a lowercase mailbox address")
        safe_text(self.display_name, "display name", 150)
        try:
            ZoneInfo(self.timezone)
        except (ValueError, KeyError):
            raise SafetyError("Configure a valid IANA timezone") from None
        if self.provider != "gmail" or self.credential_backend not in {"keychain", "env"}:
            raise SafetyError("Supported provider: gmail; credential backend: keychain or env")
        # Ceilings stay under Google Workspace's ~2,000/day so one tool cannot exhaust the mailbox.
        for field, low, high in [("min_interval_seconds", 1, 86400), ("max_messages_24h", 1, 1000),
                                 ("max_recipients_24h", 1, 1000), ("send_start_hour", 0, 23), ("send_end_hour", 1, 24)]:
            value = getattr(self, field)
            if type(value) is not int or not low <= value <= high:
                raise SafetyError(f"{field} must be an integer from {low} to {high}")
        if self.send_start_hour >= self.send_end_hour:
            raise SafetyError("send_start_hour must be before send_end_hour")
        if type(self.weekdays_only) is not bool:
            raise SafetyError("weekdays_only must be true or false")
        for field in ["signature_text_path", "signature_html_path"]:
            path = Path(getattr(self, field)).expanduser()
            if not path.is_absolute() or not path.is_file() or path.stat().st_size > 65536:
                raise SafetyError(f"{field} must be an absolute path to a file <=64 KiB")
        self.signatures()
        return self

    def signatures(self):
        from .message import validate_html

        text = Path(self.signature_text_path).expanduser().read_text()
        html = Path(self.signature_html_path).expanduser().read_text()
        if not text.strip() or not html.strip() or self.address not in text or self.address not in html:
            raise SafetyError("Both signatures must be nonempty and include the sender email")
        validate_html(html, allow_signature_images=True)
        return text.strip(), html.strip()

    def fingerprint(self):
        return digest({"config": asdict(self), "signatures": self.signatures()})

    def state_dir(self):
        # A fixed mailbox key is shared across working directories and installations.
        return Path.home() / ".local" / "share" / "safe-email-send" / digest(self.address)[:24]


ENV_FIELDS = {f"SAFE_EMAIL_{field.upper()}": field for field in Config.__dataclass_fields__}
ENV_FIELDS["SAFE_EMAIL_SIGNATURE_TEXT_PATH"] = "signature_text_path"
ENV_FIELDS["SAFE_EMAIL_SIGNATURE_HTML_PATH"] = "signature_html_path"


def read_env_file(path):
    """Simple literal KEY=VALUE format, no shell expansion or executable dotenv."""
    result = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in {*ENV_FIELDS, "SAFE_EMAIL_APP_PASSWORD"} or key in result:
            raise SafetyError("Unknown or duplicate key in explicit environment file")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key == "SAFE_EMAIL_APP_PASSWORD":
            if value:
                raise SafetyError("Do not store the app password in an environment file; use Keychain or process injection")
            continue
        result[key] = value
    return result


def resolve(values=None, *, environ=None, saved=True):
    environ = os.environ if environ is None else environ
    data = {}
    if saved and config_path().exists():
        data = json.loads(config_path().read_text())
    merged = dict(values or {})
    merged.update({key: value for key, value in environ.items() if key.startswith("SAFE_EMAIL_")})
    for key, value in merged.items():
        if key == "SAFE_EMAIL_APP_PASSWORD":
            continue
        if key not in ENV_FIELDS:
            raise SafetyError("Unknown SAFE_EMAIL environment variable")
        field = ENV_FIELDS[key]
        if field in {"min_interval_seconds", "max_messages_24h", "max_recipients_24h", "send_start_hour", "send_end_hour"}:
            try:
                value = int(value)
            except (ValueError, TypeError):
                raise SafetyError(f"Invalid numeric configuration: {field}") from None
        if field == "weekdays_only" and not isinstance(value, bool):
            if str(value).lower() not in {"true", "false"}:
                raise SafetyError("SAFE_EMAIL_WEEKDAYS_ONLY must be true or false")
            value = str(value).lower() == "true"
        if field.endswith("_path"):
            value = str(Path(value).expanduser())
        data[field] = value
    try:
        return Config(**data).validate()
    except TypeError:
        raise SafetyError("Configuration incomplete; run setup with your own identity, timezone and signatures") from None


def save_config(config):
    # Only fields from the dataclass can be persisted; secrets are never included.
    write_private(config_path(), json.dumps(asdict(config), indent=2) + "\n")
