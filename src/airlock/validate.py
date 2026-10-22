"""Post-quarantine validation.

Even with schema-constrained sampling, every payload is re-validated with
``extra="forbid"`` and a runtime sentence-index range check. Anything that fails is
placed in the unparsed bucket rather than trusted.
"""

from __future__ import annotations

from pydantic import ValidationError

from .schema import Extraction


def sentence_ids_valid(extraction: Extraction, n_sentences: int) -> bool:
    """Ensure every emitted sentence index points at a real sentence."""
    if n_sentences <= 0:
        return False
    if any(idx >= n_sentences for idx in extraction.evidence):
        return False
    if extraction.deadline_sentence is not None and extraction.deadline_sentence >= n_sentences:
        return False
    if extraction.amount_sentence is not None and extraction.amount_sentence >= n_sentences:
        return False
    return True


def validate_extraction(payload: dict, n_sentences: int) -> Extraction | None:
    """Parse and range-check a model payload, returning None when invalid."""
    try:
        extraction = Extraction.model_validate(payload)
    except ValidationError:
        return None
    if not sentence_ids_valid(extraction, n_sentences):
        return None
    return extraction
