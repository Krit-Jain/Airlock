"""Tiny taint tracking.

Every value that could influence a side effect carries an origin. Values derived from
untrusted message text are tagged ``DERIVED_FROM_UNTRUSTED`` and can only reach a sink
when a human approval token is present.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar

T = TypeVar("T")


class Origin(str, Enum):
    CODE = "code"
    USER = "user"
    DERIVED_FROM_UNTRUSTED = "derived_from_untrusted"


@dataclass(frozen=True)
class Tagged(Generic[T]):
    value: T
    origin: Origin


def code(value: T) -> Tagged[T]:
    return Tagged(value, Origin.CODE)


def user(value: T) -> Tagged[T]:
    return Tagged(value, Origin.USER)


def untrusted(value: T) -> Tagged[T]:
    return Tagged(value, Origin.DERIVED_FROM_UNTRUSTED)
