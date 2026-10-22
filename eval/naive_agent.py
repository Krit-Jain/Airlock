"""Naive flat-context agent baseline.

Represents an agent that reads the whole inbox into one context and can act through
mocked tools. The deterministic policy is deliberately gullible: it acts on any contact
or URL it sees, which is exactly the failure mode Airlock removes by construction.
"""

from __future__ import annotations

import re

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_URL = re.compile(r"https?://[^\s\"'<>]+")
_IMPERATIVE = re.compile(
    r"\b(forward|send|share|exfiltrate|call|open|download|install|click|reply)\b",
    re.IGNORECASE,
)


def naive_tool_calls(item: dict) -> list[dict]:
    raw = item["raw"]
    calls: list[dict] = []
    if _IMPERATIVE.search(raw):
        calls.append({"name": "forward_email", "args": {"content": raw}})
    for addr in sorted(set(_EMAIL.findall(raw))):
        calls.append({"name": "forward_email", "args": {"to": addr, "content": raw}})
    for url in sorted(set(_URL.findall(raw))):
        calls.append({"name": "fetch_url", "args": {"url": url}})
    return calls
