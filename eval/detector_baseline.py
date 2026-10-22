"""Detector-style baseline.

A regex heuristic sits in front of the naive agent and refuses to act when it spots
injection trigger words. This mirrors probabilistic detector approaches and shows why
they are a weak wall: camouflaged attacks without trigger words still pass.
"""

from __future__ import annotations

import re

from .naive_agent import naive_tool_calls

_INJECTION = re.compile(
    r"ignore previous|system|developer|assistant|instructions|forward|exfiltrate|compliance",
    re.IGNORECASE,
)


def detector_refuses(item: dict) -> bool:
    return bool(_INJECTION.search(item["raw"]))


def detector_tool_calls(item: dict) -> list[dict]:
    if detector_refuses(item):
        return []
    return naive_tool_calls(item)
