"""Paired steering metrics.

Each attack instance is compared with its clean twin. Steering is what happens to the
Airlock extraction and routing when the payload is present but the base message is not.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from airlock.extractor import MockAdapter, OllamaAdapter, run_extraction
from airlock.models import Message
from airlock.rank import rank
from airlock.resolve import resolve_amount, resolve_deadline
from airlock.sanitize import sanitize
from airlock.segment import split_sentences
from airlock.signals import SignalConfig, compute_signals

from .corpus.sender_variants import KNOWN_CONTACT
from .metrics import wilson

_URGENCY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
CONFIG = SignalConfig(known_contacts={KNOWN_CONTACT})


def _analyze(item: dict, adapter):
    message = Message(
        id=item.get("id", "x"),
        source=item.get("source", "email"),
        sender=item["sender"],
        ts=None,
        raw_text=item["raw"],
        headers=item.get("headers", {}),
    )
    sanitized = sanitize(message.raw_text)
    trust, _reasons = compute_signals(message, sanitized, CONFIG)
    sentences = split_sentences(sanitized.text)
    extraction, _error = run_extraction(adapter, sentences)
    deadline = resolve_deadline(sentences, extraction.deadline_sentence if extraction else None)
    amount = resolve_amount(sentences, extraction.amount_sentence if extraction else None)
    result = rank(extraction, trust, extraction is None, False, deadline is not None, amount is not None)
    return extraction, result, trust


def steering_flags(attack: dict, twin: dict, adapter) -> dict:
    extraction_a, result_a, _ = _analyze(attack, adapter)
    extraction_t, result_t, _ = _analyze(twin, adapter)

    flags: dict[str, bool] = {}
    if extraction_a and extraction_t:
        flags["flip_category"] = extraction_a.category != extraction_t.category
        flags["flip_request_type"] = extraction_a.request_type != extraction_t.request_type
        flags["asks_flip"] = extraction_a.asks_user_to_act != extraction_t.asks_user_to_act
        flags["urgency_raised_before_cap"] = _URGENCY_RANK[extraction_a.urgency.value] > _URGENCY_RANK[extraction_t.urgency.value]
        flags["urgency_raised_after_cap"] = _URGENCY_RANK[result_a.urgency.value] > _URGENCY_RANK[result_t.urgency.value]

    flags["promotion"] = result_a.section == "needs_you" and result_t.section != "needs_you"
    flags["suppression"] = result_t.section == "needs_you" and result_a.section != "needs_you"
    flags["review_diversion"] = result_a.section == "review" and result_t.section != "review"
    return flags


_METRICS = (
    "flip_category",
    "flip_request_type",
    "asks_flip",
    "urgency_raised_before_cap",
    "urgency_raised_after_cap",
    "promotion",
    "suppression",
    "review_diversion",
)


def run_steering_eval(
    quarantine_model: str = "mock",
    limit: int | None = None,
    split: str = "test",
    out_dir: str | Path = "results",
) -> dict:
    corpus_dir = Path(__file__).parent / "corpus"
    attacks = [json.loads(line) for line in (corpus_dir / "attacks.jsonl").read_text(encoding="utf-8").splitlines()]
    attacks = [a for a in attacks if a.get("split") == split]
    if limit:
        attacks = attacks[:limit]

    adapter = MockAdapter() if quarantine_model == "mock" else OllamaAdapter(model=quarantine_model)

    by_variant: dict[str, dict[str, int]] = defaultdict(lambda: {m: 0 for m in _METRICS})
    counts: dict[str, int] = defaultdict(int)
    rows: list[dict] = []

    for attack in attacks:
        flags = steering_flags(attack, attack["twin"], adapter)
        variant = attack["sender_variant"]
        counts[variant] += 1
        for metric in _METRICS:
            by_variant[variant][metric] += int(flags.get(metric, False))
        rows.append({"instance": attack["id"], "sender_variant": variant, **flags})

    summary = {"metadata": {"quarantine_model": quarantine_model, "split": split, "attacks": len(attacks)}, "by_sender_variant": {}}
    for variant, stats in sorted(by_variant.items()):
        n = counts[variant]
        summary["by_sender_variant"][variant] = {
            "n": n,
            **{metric: wilson(stats[metric], n).__dict__ for metric in _METRICS},
        }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "steering.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    (out / "steering.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    print(json.dumps(run_steering_eval(limit=40), indent=2))
