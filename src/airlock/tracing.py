"""Optional Sentry tracing.

Spans carry hashes, enums, latency, and token counts only. Message text and model
reasoning are never recorded. Tracing is a no-op unless a DSN is configured.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from typing import Iterator

import sentry_sdk


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def init_tracing(dsn: str | None = None, environment: str = "development") -> bool:
    if not dsn:
        return False
    sentry_sdk.init(
        dsn=dsn,
        environment=environment,
        traces_sample_rate=1.0,
    )
    return True


@contextmanager
def span(name: str, **tags: object) -> Iterator[None]:
    if sentry_sdk.Hub.current.client is None:
        yield
        return
    with sentry_sdk.start_span(op=name) as current:
        for key, value in tags.items():
            current.set_tag(key, value)
        yield
