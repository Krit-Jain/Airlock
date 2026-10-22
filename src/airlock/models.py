"""Core data types shared across the pipeline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from .schema import Category, RequestType, Urgency


class TrustLabel(str, Enum):
    VERIFIED_KNOWN = "verified_known"
    KNOWN_UNVERIFIED = "known_unverified"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"


class TrustReason(str, Enum):
    AUTH_PASS = "auth_pass"
    AUTH_FAIL = "auth_fail"
    DOMAIN_MISMATCH = "domain_mismatch"
    DISPLAY_NAME_SPOOF = "display_name_spoof"
    HIDDEN_TEXT = "hidden_text"
    INVISIBLE_UNICODE = "invisible_unicode"
    LINK_MISMATCH = "link_mismatch"
    RISKY_ATTACHMENT = "risky_attachment"
    KNOWN_CONTACT = "known_contact"
    FIRST_TIME_SENDER = "first_time_sender"
    UNVERIFIED_CHAT = "unverified_chat"
    MANY_LINKS = "many_links"


@dataclass
class Message:
    """A single ingested message before and during quarantine.

    ``raw_text`` and the resolved quote text are kept only on the local side and are
    never returned to the model, MCP clients, or traces.
    """

    id: str
    source: str
    sender: str
    ts: datetime | None
    raw_text: str
    headers: dict[str, str] = field(default_factory=dict)
    sanitized_text: str = ""
    sentences: list[str] = field(default_factory=list)
    trust: TrustLabel = TrustLabel.UNKNOWN
    trust_reasons: list[TrustReason] = field(default_factory=list)
    hidden_text_detected: bool = False


@dataclass
class ResolvedAmount:
    """A code-parsed monetary amount. Never contains model output."""

    value: float
    currency: str | None = None


class ResolvedRecord(BaseModel):
    """The typed, MCP-safe record for one message.

    This deliberately contains no sender string and no quote text. Sender and quotes are
    human-only rendering inputs and are kept out of any machine-facing surface.
    """

    message_id: str
    source: str
    category: Category | None = None
    urgency: Urgency | None = None
    request_type: RequestType | None = None
    asks_user_to_act: bool | None = None
    trust: TrustLabel
    trust_reasons: list[TrustReason] = Field(default_factory=list)
    deadline: datetime | None = None
    amount: ResolvedAmount | None = None
    evidence_refs: list[int] = Field(default_factory=list)
    unparsed: bool = False


@dataclass
class BriefItem:
    """A human-only rendering record, including quote text."""

    message_id: str
    sender: str
    trust: TrustLabel
    trust_reasons: list[TrustReason]
    category: Category | None
    request_type: RequestType | None
    urgency: Urgency | None
    asks_user_to_act: bool | None
    quotes: list[str]
    deadline: datetime | None
    amount: ResolvedAmount | None
    ts: datetime | None
    section: str = "fyi"


def message_id_for(source: str, sender: str, raw_text: str) -> str:
    """Stable content-derived id used for resumable processing."""
    digest = hashlib.sha256(f"{source}\x00{sender}\x00{raw_text}".encode("utf-8")).hexdigest()
    return digest[:16]
