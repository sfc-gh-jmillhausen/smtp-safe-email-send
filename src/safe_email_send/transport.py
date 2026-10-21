"""Finite, verified-TLS SMTP with conservative ambiguous-DATA handling."""

import smtplib
import ssl
from dataclasses import dataclass


@dataclass(frozen=True)
class Outcome:
    state: str
    reason: str
    pause: bool = False


def rejection(code):
    # A numeric 4xx/5xx alone cannot reliably distinguish policy from bad addresses.
    # Pause on every explicit server rejection rather than probing limits repeatedly.
    return Outcome("FAILED", f"SMTP rejection {int(code)}; manual review required", True)


class Session:
    """One authenticated SMTP connection reused across a run of sends.

    Any non-accepted outcome closes the connection so the next send starts clean.
    A reused connection that drops before DATA reconnects once; once DATA has
    started the outcome is UNKNOWN and never retried here.
    """

    def __init__(self, config, password, factory=smtplib.SMTP):
        self.config, self.password, self.factory = config, password, factory
        self.server = None

    def _connect(self):
        self.server = self.factory("smtp.gmail.com", 587, timeout=30)
        self.server.ehlo()
        self.server.starttls(context=ssl.create_default_context())
        self.server.ehlo()
        self.server.login(self.config.address, self.password)

    def send(self, item):
        reused = self.server is not None
        outcome = self._attempt(item)
        if reused and outcome.state == "RETRY":
            outcome = self._attempt(item)
        if outcome.state != "ACCEPTED":
            self.close()
        return outcome

    def _attempt(self, item):
        data_started = False
        try:
            if self.server is None:
                self._connect()
            code, _ = self.server.mail(self.config.address)
            if code != 250:
                return rejection(code)
            code, _ = self.server.rcpt(item["to"])
            if code not in {250, 251}:
                return rejection(code)
            data_started = True
            code, _ = self.server.data(item["mime"].encode("ascii"))
            if code != 250:
                return rejection(code)
            return Outcome("ACCEPTED", "Gmail accepted submission; recipient delivery unverified")
        except smtplib.SMTPResponseException as error:
            return rejection(error.smtp_code)
        except (ssl.SSLError, smtplib.SMTPNotSupportedError):
            return Outcome("FAILED", "TLS/authentication security requirement failed", True)
        except (OSError, smtplib.SMTPServerDisconnected):
            self.close()
            return (Outcome("UNKNOWN", "Connection lost during submission; do not resend", True)
                    if data_started else Outcome("RETRY", "Connection failed before DATA; bounded retry"))
        except Exception:
            return Outcome("UNKNOWN" if data_started else "FAILED", "Unexpected transport failure; review required", True)

    def close(self):
        if self.server is not None:
            server, self.server = self.server, None
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def submit(config, password, item, factory=smtplib.SMTP):
    session = Session(config, password, factory)
    try:
        return session.send(item)
    finally:
        session.close()


def check_login(config, password, factory=smtplib.SMTP):
    server = factory("smtp.gmail.com", 587, timeout=30)
    try:
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(config.address, password)
    finally:
        server.close()