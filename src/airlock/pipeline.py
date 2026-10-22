"""End-to-end message processing pipeline."""

from __future__ import annotations

from .extractor import ModelAdapter, run_extraction
from .models import Message, ResolvedRecord
from .rank import rank
from .resolve import resolve_amount, resolve_deadline
from .sanitize import sanitize
from .segment import split_sentences
from .signals import SignalConfig, compute_signals
from .store import Store


def process_message(
    message: Message,
    adapter: ModelAdapter,
    config: SignalConfig,
    store: Store,
    disputed: bool = False,
) -> ResolvedRecord:
    sanitized = sanitize(message.raw_text)
    message.sanitized_text = sanitized.text

    message.trust, message.trust_reasons = compute_signals(message, sanitized, config)
    message.sentences = split_sentences(sanitized.text)

    extraction, _error = run_extraction(adapter, message.sentences)
    unparsed = extraction is None

    deadline = resolve_deadline(message.sentences, extraction.deadline_sentence if extraction else None)
    amount = resolve_amount(message.sentences, extraction.amount_sentence if extraction else None)

    result = rank(
        extraction,
        message.trust,
        unparsed,
        disputed,
        deadline is not None,
        amount is not None,
    )

    store.save_message(
        message=message,
        extraction=extraction,
        urgency=result.urgency,
        deadline=deadline,
        amount=amount,
        section=result.section,
        unparsed=unparsed,
        disputed=disputed,
    )
    record = store.get_record(message.id)
    assert record is not None
    return record


def process_messages(
    messages: list[Message],
    adapter: ModelAdapter,
    config: SignalConfig,
    store: Store,
    disputed: bool = False,
) -> list[ResolvedRecord]:
    records: list[ResolvedRecord] = []
    for message in messages:
        if store.is_processed(message.id):
            record = store.get_record(message.id)
            if record is not None:
                records.append(record)
                continue
        records.append(process_message(message, adapter, config, store, disputed))
    return records
