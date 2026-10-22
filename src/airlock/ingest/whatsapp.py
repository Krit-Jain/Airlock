"""WhatsApp chat export ingestion.

Supports the common Android and iOS export formats, and appends untimestamped
continuation lines to the previous message.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..models import Message, message_id_for

_ANDROID = re.compile(r"^(\d{1,2}/\d{1,2}/\d{2,4}),\s+(\d{1,2}:\d{2}(?:\s?[AP]M)?)\s*-\s*(.+?):\s*(.*)$")
_IOS = re.compile(r"^\[(\d{1,2}/\d{1,2}/\d{2,4}),\s+(\d{1,2}:\d{2}:\d{2}(?:\s?[AP]M)?)\]\s*(.+?):\s*(.*)$")


def _formats(dayfirst: bool) -> list[str]:
    month_first = [
        "%m/%d/%y %I:%M %p",
        "%m/%d/%Y %I:%M %p",
        "%m/%d/%y %H:%M",
        "%m/%d/%Y %H:%M",
        "%m/%d/%y %I:%M:%S %p",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]
    day_first = [fmt.replace("%m/%d", "%d/%m") for fmt in month_first]
    return day_first + month_first if dayfirst else month_first + day_first


def _parse_ts(date_str: str, time_str: str, dayfirst: bool) -> datetime | None:
    raw = f"{date_str} {time_str.strip().upper()}"
    for fmt in _formats(dayfirst):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def parse_whatsapp(path: str | Path, dayfirst: bool = False) -> list[Message]:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    messages: list[Message] = []
    current: Message | None = None

    for line in lines:
        match = _ANDROID.match(line) or _IOS.match(line)
        if match:
            if current is not None:
                messages.append(current)
            date_str, time_str, sender, text = match.groups()
            ts = _parse_ts(date_str, time_str, dayfirst)
            current = Message(
                id=message_id_for("whatsapp", sender, text),
                source="whatsapp",
                sender=sender.strip(),
                ts=ts,
                raw_text=text.strip(),
                headers={},
            )
        elif current is not None and line.strip():
            current.raw_text = f"{current.raw_text}\n{line.strip()}"

    if current is not None:
        messages.append(current)
    return messages
