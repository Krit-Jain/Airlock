"""Worst-case reachability analysis (deterministic, no model).

Assumes the quarantine model is fully compromised and can emit any valid Extraction.
Enumerates the schema space for each trust label and reports what an attacker could
achieve: which sections and capped urgencies are reachable, and which actions a
compromised record could propose.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product

from airlock.models import TrustLabel
from airlock.rank import rank
from airlock.schema import Category, Extraction, RequestType, Urgency

_URGENCY_ORDER = [Urgency.NONE, Urgency.LOW, Urgency.MEDIUM, Urgency.HIGH]


def _proposable_actions(section: str) -> tuple[str, ...]:
    if section == "needs_you":
        return ("create_event", "flag_for_reply")
    if section == "deadlines_amounts":
        return ("create_event",)
    return ("archive",)


@dataclass
class Reach:
    trust: TrustLabel
    sections: tuple[str, ...]
    max_urgency_any: str
    needs_you_reachable: bool
    max_urgency_in_needs_you: str | None
    proposable_actions: tuple[str, ...]


def _enumerate() -> list[tuple]:
    return list(product(Category, Urgency, RequestType, [False, True], [False, True], [False, True]))


def reach_for_trust(trust: TrustLabel) -> Reach:
    sections: set[str] = set()
    actions: set[str] = set()
    max_urgency = -1
    max_needs_you = -1
    needs_you = False

    for category, urgency, request_type, asks, has_deadline, has_amount in _enumerate():
        extraction = Extraction(
            category=category,
            urgency=urgency,
            request_type=request_type,
            asks_user_to_act=asks,
            evidence=[],
        )
        result = rank(extraction, trust, unparsed=False, disputed=False, has_deadline=has_deadline, has_amount=has_amount)
        sections.add(result.section)
        actions.update(_proposable_actions(result.section))
        rank_index = _URGENCY_ORDER.index(result.urgency)
        max_urgency = max(max_urgency, rank_index)
        if result.section == "needs_you":
            needs_you = True
            max_needs_you = max(max_needs_you, rank_index)

    return Reach(
        trust=trust,
        sections=tuple(sorted(sections)),
        max_urgency_any=_URGENCY_ORDER[max_urgency].value if max_urgency >= 0 else "none",
        needs_you_reachable=needs_you,
        max_urgency_in_needs_you=_URGENCY_ORDER[max_needs_you].value if needs_you else None,
        proposable_actions=tuple(sorted(actions)),
    )


def worst_case_table() -> list[Reach]:
    order = [TrustLabel.VERIFIED_KNOWN, TrustLabel.KNOWN_UNVERIFIED, TrustLabel.UNKNOWN, TrustLabel.SUSPICIOUS]
    return [reach_for_trust(trust) for trust in order]


def render_markdown() -> str:
    lines = [
        "| Trust label | Reaches needs_you | Max urgency in needs_you | Max urgency anywhere | Proposable actions |",
        "| --- | --- | --- | --- | --- |",
    ]
    for reach in worst_case_table():
        lines.append(
            f"| {reach.trust.value} | {'yes' if reach.needs_you_reachable else 'no'} | "
            f"{reach.max_urgency_in_needs_you or '-'} | {reach.max_urgency_any} | "
            f"{', '.join(reach.proposable_actions)} |"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_markdown())
