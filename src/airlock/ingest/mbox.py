"""Email ingestion for ``.mbox`` and ``.eml`` files."""

from __future__ import annotations

import mailbox
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path

from ..models import Message, message_id_for


def _decode(payload: bytes | str | None, charset: str | None) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    return payload.decode(charset or "utf-8", errors="replace")


def _body_text(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return _decode(part.get_payload(decode=True), part.get_content_charset())
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                return _decode(part.get_payload(decode=True), part.get_content_charset())
        return ""
    return _decode(msg.get_payload(decode=True), msg.get_content_charset())


def _from_email_message(msg) -> Message:
    sender = msg.get("From", "unknown")
    raw = _body_text(msg)
    ts = None
    if msg.get("Date"):
        try:
            ts = parsedate_to_datetime(msg.get("Date"))
        except (TypeError, ValueError):
            ts = None
    headers = {str(k): str(v) for k, v in msg.items()}
    return Message(
        id=message_id_for("email", sender, raw),
        source="email",
        sender=sender,
        ts=ts,
        raw_text=raw,
        headers=headers,
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
