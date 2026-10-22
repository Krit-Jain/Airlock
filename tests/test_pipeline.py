from airlock.extractor import MockAdapter
from airlock.models import Message
from airlock.pipeline import process_message
from airlock.signals import SignalConfig


def test_process_message_with_mock(store):
    message = Message(
        id="m1",
        source="email",
        sender="Alice <alice@example.com>",
        ts=None,
        raw_text="Please reply by Friday. The invoice of $120 is due tomorrow.",
    )
    record = process_message(message, MockAdapter(), SignalConfig.empty(), store)
    assert record.message_id == "m1"
    assert not record.unparsed
    assert record.category is not None
    assert record.trust.value in {"verified_known", "known_unverified", "unknown", "suspicious"}


def test_unparsed_goes_to_review(store):
    message = Message(
        id="m2",
        source="email",
        sender="bob@example.com",
        ts=None,
        raw_text="a sentence",
    )
    # An adapter that always returns malformed JSON forces the unparsed bucket.
    adapter = MockAdapter()
    adapter.extract = lambda sentences: "{not json"

    record = process_message(message, adapter, SignalConfig.empty(), store)
    assert record.unparsed is True
    assert record.category is None
