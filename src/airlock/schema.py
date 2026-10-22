"""The quarantine schema.

The schema is the core security boundary of Airlock. The quarantined model may only
emit values described here: closed enums, booleans, and sentence indices. There are no
free-text fields. The JSON schema passed to Ollama is generated from this Pydantic model
so the two can never drift, and every response is re-validated with ``extra="forbid"``.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, conint

# Upper bound for sentence indices emitted by the model. Runtime validation additionally
# checks that every index is strictly less than the number of sentences in the message.
MAX_SENT = 200


class Category(str, Enum):
    PERSONAL = "personal"
    WORK = "work"
    NEWSLETTER = "newsletter"
    RECEIPT_OR_BILL = "receipt_or_bill"
    DELIVERY = "delivery"
    SECURITY_ALERT = "security_alert"
    GROUP_CHAT = "group_chat"
    SCAM_SUSPECT = "scam_suspect"
    OTHER = "other"


class Urgency(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RequestType(str, Enum):
    NONE = "none"
    REPLY_NEEDED = "reply_needed"
    PAYMENT = "payment"
    MEETING = "meeting"
    DEADLINE = "deadline"
    SHARE_INFO = "share_info"
    CLICK_LINK = "click_link"
    INSTALL_OR_RUN = "install_or_run"
    OTHER = "other"


class Extraction(BaseModel):
    """The only shape a quarantined model may produce."""

    model_config = ConfigDict(extra="forbid")

    category: Category
    urgency: Urgency
    request_type: RequestType
    asks_user_to_act: bool
    evidence: list[conint(ge=0, le=MAX_SENT)] = Field(max_length=3)
    deadline_sentence: conint(ge=0, le=MAX_SENT) | None = None
    amount_sentence: conint(ge=0, le=MAX_SENT) | None = None


def _dereference(schema: dict[str, Any]) -> dict[str, Any]:
    """Inline ``$defs`` references so the schema is a flat object Ollama can consume."""

    def resolve(node: Any, defs: dict[str, Any]) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                ref = node["$ref"]
                if not ref.startswith("#/$defs/"):
                    raise ValueError(f"Unsupported $ref in schema: {ref}")
                name = ref.removeprefix("#/$defs/")
                return resolve(defs[name], defs)
            return {key: resolve(value, defs) for key, value in node.items()}
        if isinstance(node, list):
            return [resolve(item, defs) for item in node]
        return node

    defs = schema.get("$defs", {})
    return resolve(schema, defs)


def ollama_schema() -> dict[str, Any]:
    """Return the flat JSON schema used for Ollama structured output."""
    raw = Extraction.model_json_schema()
    flat = _dereference(raw)
    flat.pop("$defs", None)
    return flat


def json_schema_string() -> str:
    """Return the schema as a compact JSON string for the system prompt."""
    import json

    return json.dumps(ollama_schema())
