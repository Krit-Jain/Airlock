"""The capability gate.

Side-effecting operations are sinks. A sink refuses ``DERIVED_FROM_UNTRUSTED`` values
unless a human approval token (created only by the CLI or local web UI) is present.
The agent and MCP clients cannot self-approve.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from .taint import Origin, Tagged


class TaintViolation(Exception):
    """Raised when an untrusted value reaches a sink without approval."""


@dataclass(frozen=True)
class ApprovalToken:
    """Created only by the CLI or local web UI, never by MCP clients."""

    token: str


def _contains_untrusted(values: list[Any]) -> bool:
    return any(
        isinstance(value, Tagged) and value.origin == Origin.DERIVED_FROM_UNTRUSTED
        for value in values
    )


def sink(fn: Callable) -> Callable:
    """Decorate a side-effecting function so untrusted values require approval."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        approval_token = kwargs.pop("approval_token", None)
        if _contains_untrusted(list(args) + list(kwargs.values())) and approval_token is None:
            raise TaintViolation(f"{fn.__name__} received an untrusted value without approval")
        return fn(*args, approval_token=approval_token, **kwargs)

    return wrapper


@sink
def write_ics(
    deadline: Tagged[datetime],
    message_id: str,
    approval_token: ApprovalToken | None = None,
) -> str:
    """Render a calendar proposal with a fixed title (never sender text)."""
    dt = deadline.value
    stamp = dt.strftime("%Y%m%dT%H%M%S")
    title = f"Deadline - message {message_id[:8]}"
    return "\n".join(
        [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//Airlock//EN",
            "BEGIN:VEVENT",
            f"UID:{message_id}@airlock.local",
            f"DTSTAMP:{stamp}",
            f"DTSTART:{stamp}",
            f"SUMMARY:{title}",
            "END:VEVENT",
            "END:VCALENDAR",
        ]
    )


def new_approval_token() -> ApprovalToken:
    """Create a fresh human approval token from a trusted context."""
    import secrets

    return ApprovalToken(token=secrets.token_urlsafe(16))
