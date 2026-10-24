"""Cross-message poisoning property test (C7).

Airlock processes each message in an isolated call with no history, so an attacker message
cannot change how a victim message is handled. This test measures that property against a
nondeterminism noise floor: the same victim is analyzed twice alone, then again with an
attack message present.
"""

from __future__ import annotations

import json
from pathlib import Path

from airlock.extractor import MockAdapter, OllamaAdapter, run_extraction
from airlock.models import Message, ResolvedRecord
from airlock.rank import rank
from airlock.resolve import resolve_amount, resolve_deadline
from airlock.sanitize import sanitize
from airlock.segment import split_sentences
from airlock.signals import SignalConfig, compute_signals

from .corpus.sender_variants import KNOWN_CONTACT

CONFIG = SignalConfig(known_contacts={KNOWN_CONTACT})


def _adapter(model: str):
    return MockAdapter() if model == "mock" else OllamaAdapter(model=model)


def _record(item: dict, adapter) -> ResolvedRecord:
    message = Message(
        id=item.get("id", "x"),
        source=item.get("source", "email"),
        sender=item["sender"],
        ts=None,
        raw_text=item["raw"],
        headers=item.get("headers", {}),
    )
    sanitized = sanitize(message.raw_text)
    trust, reasons = compute_signals(message, sanitized, CONFIG)
    sentences = split_sentences(sanitized.text)
    extraction, _error = run_extraction(adapter, sentences)
    deadline = resolve_deadline(sentences, extraction.deadline_sentence if extraction else None)
    amount = resolve_amount(sentences, extraction.amount_sentence if extraction else None)
    result = rank(extraction, trust, extraction is None, False, deadline is not None, amount is not None)
    return ResolvedRecord(
        message_id=message.id,
        source=message.source,
        category=extraction.category if extraction else None,
        urgency=result.urgency,
        request_type=extraction.request_type if extraction else None,
        asks_user_to_act=extraction.asks_user_to_act if extraction else None,
        trust=trust,
        trust_reasons=reasons,
        deadline=deadline,
        amount=amount,
        evidence_refs=list(extraction.evidence) if extraction else [],
        unparsed=extraction is None,
    )


def _signature(item: dict, adapter) -> str:
    return _record(item, adapter).model_dump_json()


def run_cross_message_test(n: int = 50, quarantine_model: str = "mock", out_dir: str | Path = "results") -> dict:
    corpus_dir = Path(__file__).parent / "corpus"
    benign = [json.loads(line) for line in (corpus_dir / "benign.jsonl").read_text(encoding="utf-8").splitlines()]
    attacks = [json.loads(line) for line in (corpus_dir / "attacks.jsonl").read_text(encoding="utf-8").splitlines()]
    benign = [b for b in benign if b.get("split") == "test"][:n]
    attacks = [a for a in attacks if a.get("split") == "test"]

    adapter = _adapter(quarantine_model)

    alone_first = [_signature(v, adapter) for v in benign]
    alone_second = [_signature(v, adapter) for v in benign]
    noise_floor = sum(1 for a, b in zip(alone_first, alone_second) if a != b)

    # Process an attack message, then the victims again, interleaved one at a time.
    _signature(attacks[0], adapter)
    with_attack = []
    for index, victim in enumerate(benign):
        if index % 5 == 0:
            _signature(attacks[(index // 5) % len(attacks)], adapter)
        with_attack.append(_signature(victim, adapter))

    changed = sum(1 for a, c in zip(alone_first, with_attack) if a != c)

    results = {
        "n": len(benign),
        "quarantine_model": quarantine_model,
        "noise_floor": noise_floor,
        "changed_with_attack": changed,
        "stable": changed <= noise_floor,
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cross_message.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results
