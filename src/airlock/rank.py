"""Deterministic ranking.

The model's urgency is capped by code-computed trust, so an attacker who steers a
message to "urgent" cannot promote an untrusted sender. Suspicious, unparsed, and
disputed messages are always routed to the "review" section regardless of model output.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import TrustLabel
from .schema import Extraction, RequestType, Urgency

_URGENCY_RANK = {
    Urgency.NONE: 0,
    Urgency.LOW: 1,
    Urgency.MEDIUM: 2,
    Urgency.HIGH: 3,
}

_TRUST_CAP = {
    TrustLabel.VERIFIED_KNOWN: Urgency.HIGH,
    TrustLabel.KNOWN_UNVERIFIED: Urgency.MEDIUM,
    TrustLabel.UNKNOWN: Urgency.LOW,
    TrustLabel.SUSPICIOUS: Urgency.LOW,
}


def capped_urgency(trust: TrustLabel, model_urgency: Urgency) -> Urgency:
    cap = _TRUST_CAP[trust]
    if _URGENCY_RANK[model_urgency] <= _URGENCY_RANK[cap]:
        return model_urgency
    return cap


@dataclass
class RankResult:
    urgency: Urgency
    section: str


def rank(
    extraction: Extraction | None,
    trust: TrustLabel,
    unparsed: bool,
    disputed: bool,
    has_deadline: bool,
    has_amount: bool,
) -> RankResult:
    if extraction is None:
        return RankResult(urgency=Urgency.NONE, section="review")

    urgency = capped_urgency(trust, extraction.urgency)

    if unparsed or trust == TrustLabel.SUSPICIOUS or disputed:
        return RankResult(urgency=urgency, section="review")

    is_request = (
        extraction.asks_user_to_act
        or extraction.request_type != RequestType.NONE
        or urgency in (Urgency.MEDIUM, Urgency.HIGH)
    )
    if is_request:
        return RankResult(urgency=urgency, section="needs_you")
    if has_deadline or has_amount:
        return RankResult(urgency=urgency, section="deadlines_amounts")
    return RankResult(urgency=urgency, section="fyi")
