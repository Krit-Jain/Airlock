"""The quarantined extraction step.

The model receives one message at a time, in isolation, at temperature zero, with no
tools and no history. It may only emit the schema. Adapters keep the model boundary
pluggable so the rest of the pipeline runs deterministically without a live model.
"""

from __future__ import annotations

import hashlib
import json
from typing import Protocol

from .schema import Category, Extraction, RequestType, Urgency, ollama_schema
from .segment import labeled_sentences
from .validate import validate_extraction

# Character cap for a single model input. Messages above this are truncated and flagged.
MAX_MODEL_INPUT_CHARS = 8000

SYSTEM_PROMPT = (
    "You classify one message into a fixed JSON schema. Return only the JSON object, "
    "nothing else.\n"
    f"category: one of {[c.value for c in Category]}\n"
    f"urgency: one of {[u.value for u in Urgency]}\n"
    f"request_type: one of {[r.value for r in RequestType]}\n"
    "asks_user_to_act: boolean\n"
    "evidence: array of up to three sentence indices that support your answer\n"
    "deadline_sentence: the index of a sentence containing a deadline, or null\n"
    "amount_sentence: the index of a sentence containing a monetary amount, or null\n"
    "Sentence indices refer to the S0..Sn labels in the message."
)


class ExtractionError(Exception):
    """Raised when a model adapter cannot produce a usable payload."""


class ModelAdapter(Protocol):
    model_tag: str

    def extract(self, sentences: list[str]) -> str:
        """Return the raw model output for one message (a JSON string)."""
        ...


class OllamaAdapter:
    """Calls a local Ollama server with schema-constrained decoding."""

    def __init__(self, model: str, host: str | None = None, num_ctx: int = 4096):
        import ollama

        self._ollama = ollama
        self.model_tag = model
        self.host = host
        self.num_ctx = num_ctx

    def extract(self, sentences: list[str]) -> str:
        user_prompt = labeled_sentences(sentences)
        response = self._ollama.chat(
            model=self.model_tag,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            format=ollama_schema(),
            think=False,
            options={
                "temperature": 0,
                "num_ctx": self.num_ctx,
            },
        )
        content = response["message"]["content"]
        # Ignore any reasoning text and keep only the final JSON content.
        return str(content).strip()


class MockAdapter:
    """Deterministic adapter used by tests and the offline demo.

    When ``fixed`` is provided it is returned verbatim. Otherwise a small keyword
    heuristic produces a plausible, stable extraction without any model.
    """

    def __init__(self, model_tag: str = "mock", fixed: Extraction | None = None):
        self.model_tag = model_tag
        self._fixed = fixed

    def extract(self, sentences: list[str]) -> str:
        extraction = self._fixed or _heuristic_extraction(sentences)
        return extraction.model_dump_json()


def _heuristic_extraction(sentences: list[str]) -> Extraction:
    joined = " ".join(sentences).lower()
    category = Category.OTHER
    if any(w in joined for w in ("newsletter", "unsubscribe", "edition", "digest")):
        category = Category.NEWSLETTER
    elif any(w in joined for w in ("invoice", "receipt", "bill", "payment due", "amount due")):
        category = Category.RECEIPT_OR_BILL
    elif any(w in joined for w in ("order", "shipped", "tracking", "delivery", "package")):
        category = Category.DELIVERY
    elif any(w in joined for w in ("security", "login attempt", "password reset", "suspicious")):
        category = Category.SECURITY_ALERT

    request_type = RequestType.NONE
    urgency = Urgency.NONE
    asks = False
    if any(w in joined for w in ("please reply", "rsvp", "confirm", "let me know", "respond")):
        request_type = RequestType.REPLY_NEEDED
        asks = True
        urgency = Urgency.MEDIUM
    elif any(w in joined for w in ("pay", "payment", "amount due", "invoice")):
        request_type = RequestType.PAYMENT
        asks = True
        urgency = Urgency.HIGH
    elif any(w in joined for w in ("click", "link", "download", "install", "open the")):
        request_type = RequestType.CLICK_LINK
        asks = True
        urgency = Urgency.MEDIUM

    evidence = [i for i in range(min(len(sentences), 2))]
    deadline = next((i for i, s in enumerate(sentences) if any(w in s.lower() for w in ("due", "deadline", "by ", "before "))), None)
    amount = next((i for i, s in enumerate(sentences) if any(w in s.lower() for w in ("$", "usd", "inr", "rs ", "amount"))), None)

    return Extraction(
        category=category,
        urgency=urgency,
        request_type=request_type,
        asks_user_to_act=asks,
        evidence=evidence,
        deadline_sentence=deadline,
        amount_sentence=amount,
    )


def run_extraction(adapter: ModelAdapter, sentences: list[str]) -> tuple[Extraction | None, str | None]:
    """Call the adapter and parse its output as an Extraction.

    Returns ``(None, error)`` when the output is unparsable or out of schema, so callers
    can place the message in the unparsed bucket without crashing.
    """
    try:
        raw = adapter.extract(sentences)
        payload = json.loads(raw)
        extraction = validate_extraction(payload, len(sentences))
        if extraction is None:
            return None, "out-of-schema payload"
        return extraction, None
    except Exception as exc:  # noqa: BLE001 - deliberately degrade to unparsed
        return None, str(exc)


def cap_sentences(sentences: list[str], max_chars: int = MAX_MODEL_INPUT_CHARS) -> tuple[list[str], bool]:
    """Cap the model input by characters, returning (kept_sentences, truncated)."""
    total = 0
    kept: list[str] = []
    for sentence in sentences:
        if kept and total + len(sentence) > max_chars:
            return kept, True
        kept.append(sentence)
        total += len(sentence)
    return kept, False


def schema_hash() -> str:
    return hashlib.sha256(json.dumps(ollama_schema(), sort_keys=True).encode("utf-8")).hexdigest()[:12]


def prompt_hash() -> str:
    return hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()[:12]
