"""Strict structured input and deterministic signed MIME preparation."""

import html
import re
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formataddr, format_datetime, make_msgid
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .config import SafetyError, address, digest, safe_text

MARKER = "safe-email-signature"
ID_PATTERN = re.compile(r"<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~@-]+>")


class SafeHTML(HTMLParser):
    TAGS = {"div", "p", "br", "strong", "b", "em", "i", "u", "a", "span",
            "table", "tbody", "tr", "td", "ul", "ol", "li", "hr"}
    ATTRS = {"style", "class", "width", "height", "cellpadding", "cellspacing", "border", "role"}

    def __init__(self, allow_signature_images=False):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.allow_signature_images = allow_signature_images

    def handle_starttag(self, tag, attrs):
        if tag not in self.TAGS and not (tag == "img" and self.allow_signature_images):
            raise SafetyError(f"Unsupported email HTML element: {tag}")
        for name, value in attrs:
            allowed = self.ATTRS | {"dir", "data-smartmail"}
            if tag == "img" and self.allow_signature_images:
                allowed |= {"src", "alt"}
            if value is None or (name not in allowed and not (tag == "a" and name == "href")):
                raise SafetyError("Unsupported email HTML attribute")
            if name == "src":
                url = urlsplit(value)
                if url.scheme != "https" or not url.hostname or url.query or url.fragment or url.username:
                    raise SafetyError("Signature images require a static HTTPS URL without query or credentials")
            if name == "href":
                url = urlsplit(value)
                if url.scheme not in {"https", "mailto", "tel"} or (url.scheme == "https" and not url.netloc):
                    raise SafetyError("Email links require https, mailto or tel")
            if name == "style" and (re.search(r"url|expression|@|\\|display\s*:|visibility|opacity|position", value, re.I)
                                     or "<" in value):
                raise SafetyError("Unsupported CSS in email HTML")

    def handle_endtag(self, tag):
        if tag not in self.TAGS:
            raise SafetyError("Unsupported closing HTML element")

    def handle_data(self, data):
        self.text.append(data)

    def handle_decl(self, decl):
        raise SafetyError("Supply an HTML fragment, not a full document")


def validate_html(value, *, allow_signature_images=False):
    parser = SafeHTML(allow_signature_images)
    try:
        parser.feed(value)
        parser.close()
    except ValueError:
        raise SafetyError("Malformed email HTML") from None
    if not "".join(parser.text).strip():
        raise SafetyError("HTML must contain visible text")


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.timestamp()
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise SafetyError("Timestamp must be ISO 8601 with timezone") from None


def message_ids(value):
    if not isinstance(value, str) or any(ord(char) < 32 for char in value):
        raise SafetyError("Invalid reply headers")
    ids = ID_PATTERN.findall(value)
    if not ids or " ".join(ids) != value or len(ids) > 30:
        raise SafetyError("Reply headers must contain space-separated RFC Message-IDs")
    return ids


def prepare_messages(config, batch, now):
    if not isinstance(batch, dict) or set(batch) - {"scope", "messages", "expires_at", "eligibility"}:
        raise SafetyError("Unknown batch fields")
    scope = batch.get("scope")
    if scope not in {"individual", "campaign"}:
        raise SafetyError("scope must be individual or campaign")
    messages = batch.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 1000:
        raise SafetyError("Batch requires 1-1000 messages")
    if len(messages) > 1 and scope != "campaign":
        raise SafetyError("Multi-message batches require campaign eligibility")
    expiry = timestamp(batch["expires_at"]) if "expires_at" in batch else now + 86400
    if not now < expiry <= now + 7 * 86400:
        raise SafetyError("Batch expiry must be in the next seven days")
    eligibility = batch.get("eligibility")
    if scope == "campaign":
        if not isinstance(eligibility, dict) or set(eligibility) != {"source", "checked_at", "valid_until", "allowed_recipients"}:
            raise SafetyError("Campaign requires source, checked_at, valid_until and allowed_recipients eligibility evidence")
        safe_text(eligibility["source"], "eligibility source", 500)
        checked = timestamp(eligibility["checked_at"])
        valid = timestamp(eligibility["valid_until"])
        if not now - 86400 <= checked <= now or not now < valid <= checked + 86400:
            raise SafetyError("Campaign eligibility must be fresh and valid for at most 24 hours")
        if not isinstance(eligibility["allowed_recipients"], list):
            raise SafetyError("allowed_recipients must be an explicit list")
        allowed = {address(item) for item in eligibility["allowed_recipients"]}
        expiry = min(expiry, valid)
    elif eligibility is not None:
        raise SafetyError("Eligibility is only accepted for campaign scope")
    signature_text, signature_html = config.signatures()
    result = []
    seen = set()
    for item in messages:
        fields = {"to", "subject", "text", "html", "source_id", "in_reply_to", "references"}
        if not isinstance(item, dict) or set(item) - fields:
            raise SafetyError("Unknown message field (CC/BCC/attachments are unsupported)")
        recipient = address(item.get("to"))
        if recipient in seen:
            raise SafetyError("Duplicate recipient in batch")
        seen.add(recipient)
        if scope == "campaign" and recipient not in allowed:
            raise SafetyError("Recipient not covered by eligibility evidence")
        subject = safe_text(item.get("subject"), "subject", 200)
        source_id = safe_text(item.get("source_id"), "source_id", 200)
        text = item.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > 50000 or "\x00" in text:
            raise SafetyError("A nonempty text body <=50000 characters is required")
        body_html = item.get("html", "<div>" + html.escape(text).replace("\n", "<br>\n") + "</div>")
        if not isinstance(body_html, str) or len(body_html) > 100000:
            raise SafetyError("Invalid HTML body")
        validate_html(body_html)
        if (MARKER in body_html or "gmail_signature" in body_html or signature_html in body_html
                or signature_text in text):
            raise SafetyError("Supply unsigned content; existing signature detected")
        signed_text = text.rstrip() + "\n\n-- \n" + signature_text + "\n"
        signed_html = body_html + f'<div class="{MARKER}">{signature_html}</div>'
        reply = item.get("in_reply_to")
        references = item.get("references")
        if reply is not None and len(message_ids(reply)) != 1:
            raise SafetyError("in_reply_to requires exactly one Message-ID")
        if references is not None:
            message_ids(references)
            if reply is None or reply not in references.split():
                raise SafetyError("References requires matching in_reply_to")
        mail = EmailMessage(policy=SMTP)
        mail["From"] = formataddr((config.display_name, config.address))
        mail["To"] = recipient
        mail["Subject"] = subject
        mail["Date"] = format_datetime(datetime.fromtimestamp(now, timezone.utc))
        mail["Message-ID"] = make_msgid(domain=config.address.split("@")[1])
        if reply:
            mail["In-Reply-To"] = reply
            mail["References"] = references or reply
        mail.set_content(signed_text, cte="quoted-printable")
        mail.add_alternative(signed_html, subtype="html", cte="quoted-printable")
        result.append({"to": recipient, "subject": subject, "source_id": source_id,
                       "message_id": str(mail["Message-ID"]), "text": signed_text,
                       "html": signed_html, "mime": mail.as_bytes().decode("ascii"),
                       "reply": reply, "content_key": digest([config.address, recipient, subject, text, body_html, reply])})
    return {"config_hash": config.fingerprint(), "scope": scope, "expires_at": expiry,
            "created_at": now, "eligibility": eligibility, "messages": result}
