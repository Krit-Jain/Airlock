"""Email ingestion for ``.mbox`` and ``.eml`` files."""

from __future__ import annotations

import mailbox
import re
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path

from bs4 import BeautifulSoup

from ..models import Message, message_id_for

_WORD_RE = re.compile(r"[a-z0-9]+")


def _decode(payload: bytes | str | None, charset: str | None) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    return payload.decode(charset or "utf-8", errors="replace")


def _part_text(msg, content_type: str) -> str:
    for part in msg.walk():
        if part.get_content_type() == content_type:
            return _decode(part.get_payload(decode=True), part.get_content_charset())
    if not msg.is_multipart() and msg.get_content_type() == content_type:
        return _decode(msg.get_payload(decode=True), msg.get_content_charset())
    return ""


def _plain_and_html(msg) -> tuple[str, str]:
    return _part_text(msg, "text/plain"), _part_text(msg, "text/html")


def _words(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def _materially_disagree(plain: str, html: str) -> bool:
    """True when the text and HTML parts describe substantially different content."""
    if not plain.strip() or not html.strip():
        return False
    plain_words = _words(plain)
    html_words = _words(BeautifulSoup(html, "html.parser").get_text(" "))
    if not plain_words or not html_words:
        return False
    overlap = len(plain_words & html_words)
    return overlap / max(len(plain_words), len(html_words)) < 0.5


def _attachments(msg) -> list[str]:
    names: list[str] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        if filename:
            names.append(filename)
    return names


def _from_email_message(msg) -> Message:
    sender = msg.get("From", "unknown")
    plain, html = _plain_and_html(msg)
    raw = plain if plain.strip() else html

    ts = None
    if msg.get("Date"):
        try:
            ts = parsedate_to_datetime(msg.get("Date"))
        except (TypeError, ValueError):
            ts = None

    headers: dict[str, list[str]] = {}
    for key, value in msg.items():
        headers.setdefault(str(key), []).append(str(value))

    return Message(
        id=message_id_for("email", sender, raw),
        source="email",
        sender=sender,
        ts=ts,
        raw_text=raw,
        headers=headers,
        attachments=_attachments(msg),
        part_mismatch=_materially_disagree(plain, html),
    )


def parse_eml(path: str | Path) -> list[Message]:
    data = Path(path).read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    msg = BytesParser(policy=policy.default).parsebytes(data)
    return [_from_email_message(msg)]


def parse_mbox(path: str | Path) -> list[Message]:
    messages: list[Message] = []
    for msg in mailbox.mbox(str(path)):
        if msg is None:
            continue
        messages.append(_from_email_message(msg))
    return messages


def parse_email(path: str | Path) -> list[Message]:
    path = Path(path)
    if path.suffix.lower() == ".eml":
        return parse_eml(path)
    return parse_mbox(path)
