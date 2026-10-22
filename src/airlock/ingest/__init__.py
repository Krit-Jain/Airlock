"""Ingest dispatcher for raw inbox and chat exports."""

from __future__ import annotations

from pathlib import Path

from ..models import Message
from .mbox import parse_email
from .whatsapp import parse_whatsapp


def load_messages(path: str | Path, dayfirst: bool = False) -> list[Message]:
    """Load messages from a ``.mbox``, ``.eml``, or WhatsApp ``.txt`` file."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".txt":
        return parse_whatsapp(path, dayfirst=dayfirst)
    return parse_email(path)
