"""WhatsApp chat export ingestion.

Supports the common Android and iOS export formats, appends untimestamped continuation
lines to the previous message, detects the date order from the file, and disambiguates
identical messages with a sequence number.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..models import Message, message_id_for

_ANDROID = re.compile(r"^(\d{1,2}/\d{1,2}/\d{2,4}),\s+(\d{1,2}:\d{2}(?:\s?[AP]M)?)\s*-\s*(.+?):\s*(.*)$")
_IOS = re.compile(r"^\[(\d{1,2}/\d{1,2}/\d{2,4}),\s+(\d{1,2}:\d{2}:\d{2}(?:\s?[AP]M)?)\]\s*(.+?):\s*(.*)$")
_DIRECTION_MARKS = "\u200e\u200f"


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


def _detect_dayfirst(date_strs: list[str]) -> bool:
    """Decide date order from the file: a component above 12 disambiguates it."""
    day_first_votes = 0
    month_first_votes = 0
    for date_str in date_strs:
        parts = date_str.split("/")
        if len(parts) < 2:
            continue
        try:
            first, second = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        if first > 12:
            day_first_votes += 1
        if second > 12:
            month_first_votes += 1
    return day_first_votes > month_first_votes


def parse_whatsapp(path: str | Path, dayfirst: bool | None = None) -> list[Message]:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()

    matches: list[tuple[re.Match, int]] = []
    for index, raw_line in enumerate(lines):
        line = raw_line.lstrip(_DIRECTION_MARKS)
        match = _ANDROID.match(line) or _IOS.match(line)
        if match:
            matches.append((match, index))

    if dayfirst is None:
        dayfirst = _detect_dayfirst([match.group(1) for match, _ in matches])

    messages: list[Message] = []
    for seq, (match, line_index) in enumerate(matches):
        date_str, time_str, sender, text = match.groups()
        ts = _parse_ts(date_str, time_str, dayfirst)

        next_line_index = matches[seq + 1][1] if seq + 1 < len(matches) else len(lines)
        continuation = [ln.strip() for ln in lines[line_index + 1 : next_line_index] if ln.strip()]
        body = "\n".join([text.strip(), *continuation]).strip()

        messages.append(
            Message(
                id=message_id_for(f"whatsapp#{seq}", sender, body),
                source="whatsapp",
                sender=sender.strip(),
                ts=ts,
                raw_text=body,
                headers={},
            )
        )
    return messages
