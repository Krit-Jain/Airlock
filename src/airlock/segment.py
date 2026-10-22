"""Deterministic sentence segmentation.

Messages are split into numbered sentences so the model only ever has to emit integer
indices rather than reproduce exact substrings. Small local models are weak at character
offsets but reliable at choosing indices.
"""

from __future__ import annotations

import re

from .schema import MAX_SENT

_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+|\n+")

# Maximum characters per sentence before it is split further.
_MAX_SENTENCE_LEN = 280


def _split_long(sentence: str, max_len: int) -> list[str]:
    if len(sentence) <= max_len:
        return [sentence]

    words = sentence.split(" ")
    chunks: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= max_len or not current:
            current = candidate
        else:
            chunks.append(current)
            current = word
    if current:
        chunks.append(current)
    return chunks


def split_sentences(text: str, max_len: int = _MAX_SENTENCE_LEN) -> list[str]:
    """Split text into a deterministic, length-capped list of sentences."""
    raw_parts = _SENTENCE_BOUNDARY.split(text.strip())
    sentences: list[str] = []
    for part in raw_parts:
        part = part.strip()
        if not part:
            continue
        sentences.extend(_split_long(part, max_len))
        if len(sentences) >= MAX_SENT:
            break
    return sentences[:MAX_SENT]


def labeled_sentences(sentences: list[str]) -> str:
    """Render sentences as ``S0: ...`` lines for the quarantine prompt."""
    return "\n".join(f"S{i}: {sentence}" for i, sentence in enumerate(sentences))
