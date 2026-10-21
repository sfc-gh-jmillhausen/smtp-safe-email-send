"""Explicit credential backends; never fall back from a secure store to a file."""

import os
import sys

from .config import SafetyError

SERVICE = "safe-email-send"


def mac_keychain():
    if sys.platform != "darwin":
        raise SafetyError("The Keychain backend requires macOS")
    from keyring.backends.macOS import Keyring

    return Keyring()


def validate_password(value):
    if not isinstance(value, str):
        raise SafetyError("Credential missing; use credential-set or explicit process secret injection")
    value = value.replace(" ", "")
    if len(value) != 16 or not value.isascii() or not value.isalpha():
        raise SafetyError("Expected a 16-letter Gmail app password")
    return value


def get_password(config):
    try:
        value = (os.environ.get("SAFE_EMAIL_APP_PASSWORD") if config.credential_backend == "env"
                 else mac_keychain().get_password(SERVICE, config.address))
        return validate_password(value)
    except SafetyError:
        raise
    except Exception:
        raise SafetyError("Keychain unavailable or locked; no credential fallback attempted") from None


def store_password(config, value):
    if config.credential_backend != "keychain":
        raise SafetyError("credential-set requires the keychain backend")
    value = validate_password(value)
    try:
        mac_keychain().set_password(SERVICE, config.address, value)
    except Exception:
        raise SafetyError("Could not save to macOS Keychain") from None
