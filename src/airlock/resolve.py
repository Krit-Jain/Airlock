"""Code-only resolution of model output.

The model emits sentence indices. This module turns those indices into quotes, dates,
and amounts using deterministic code. This is the "code reads" half of the design:
nothing the attacker wrote is ever copied back out by a model.
"""

from __future__ import annotations

import re
from datetime import datetime

import dateparser

from .models import ResolvedAmount

_AMOUNT_PATTERNS = [
    re.compile(r"(?P<currency>[$€£₹])\s*(?P<value>\d[\d,]*(?:\.\d+)?)"),
    re.compile(r"(?P<value>\d[\d,]*(?:\.\d+)?)\s*(?P<currency>USD|EUR|INR|GBP|Rs\.?)", re.IGNORECASE),
]


def resolve_quotes(sentences: list[str], ids: list[int]) -> list[str]:
    """Return the quoted sentence text for the given indices."""
    return [sentences[i] for i in ids if 0 <= i < len(sentences)]


def resolve_deadline(sentences: list[str], deadline_sentence: int | None) -> datetime | None:
    if deadline_sentence is None or not (0 <= deadline_sentence < len(sentences)):
        return None
    text = sentences[deadline_sentence]
    parsed = dateparser.parse(text, settings={"PREFER_DATES_FROM": "future"})
    return parsed


def _parse_amount_value(raw: str) -> float:
    return float(raw.replace(",", ""))


def resolve_amount(sentences: list[str], amount_sentence: int | None) -> ResolvedAmount | None:
    if amount_sentence is None or not (0 <= amount_sentence < len(sentences)):
        return None
    text = sentences[amount_sentence]
    for pattern in _AMOUNT_PATTERNS:
        match = pattern.search(text)
        if match:
            value = _parse_amount_value(match.group("value"))
            currency = match.group("currency").upper().strip(".")
            return ResolvedAmount(value=value, currency=currency or None)
    return None
