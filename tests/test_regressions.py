"""Regression tests for the evaluation-spec correctness fixes."""

from __future__ import annotations

from airlock.extractor import cap_sentences
from airlock.ingest.mbox import parse_eml
from airlock.ingest.whatsapp import parse_whatsapp
from airlock.models import Message, TrustLabel, TrustReason
from airlock.sanitize import sanitize, strip_invisible
from airlock.signals import SignalConfig, compute_signals

_MULTIPART = (
    b'From: Alice <alice@example.com>\n'
    b'Subject: Hello\n'
    b'MIME-Version: 1.0\n'
    b'Content-Type: multipart/alternative; boundary="b"\n'
    b'\n'
    b'--b\n'
    b'Content-Type: text/plain; charset="utf-8"\n'
    b'\n'
    b'Short plain body.\n'
    b'--b\n'
    b'Content-Type: text/html; charset="utf-8"\n'
    b'\n'
    b'<p>An entirely different HTML body about invoices and payments.</p>\n'
    b'--b--\n'
)


def test_topmost_authentication_results_is_used(tmp_path):
    path = tmp_path / "dup.eml"
    path.write_bytes(
        b"Authentication-Results: example.com; spf=fail\n"
        b"Authentication-Results: evil.test; spf=pass dkim=pass dmarc=pass\n"
        b"From: Alice <alice@example.com>\n"
        b"Subject: hi\n\nbody\n"
    )
    message = parse_eml(path)[0]
    assert message.headers["Authentication-Results"][0].endswith("spf=fail")
    label, reasons = compute_signals(message, sanitize(message.raw_text))
    assert label == TrustLabel.SUSPICIOUS
    assert TrustReason.AUTH_FAIL in reasons


def test_multipart_parts_are_compared_and_flagged(tmp_path):
    path = tmp_path / "multi.eml"
    path.write_bytes(_MULTIPART)
    message = parse_eml(path)[0]
    assert message.part_mismatch is True
    _, reasons = compute_signals(message, sanitize(message.raw_text))
    assert TrustReason.PART_MISMATCH in reasons


def test_invisible_chars_are_stripped_from_model_input():
    result = sanitize("visible\u200bhiddentext\u202eevil")
    assert "\u200b" not in result.text
    assert "\u202e" not in result.text
    assert strip_invisible("a\u200cb") == "ab"


def test_only_dangerous_invisible_classes_are_flagged():
    assert sanitize("hello\u200dworld").invisible_unicode_detected is False  # ZWJ
    assert sanitize("hello\u200cworld").invisible_unicode_detected is False  # ZWNJ
    assert sanitize("heart\ufe0f").invisible_unicode_detected is False  # VS16
    assert sanitize("hi\u200bthere").invisible_unicode_detected is True  # ZWSP
    assert sanitize("hi\u202ethere").invisible_unicode_detected is True  # bidi override
    assert sanitize("x\U000e0041y").invisible_unicode_detected is True  # tag block


def test_hidden_css_does_not_match_legitimate_values():
    assert sanitize('<p style="opacity:0.8">visible</p>').hidden_text_detected is False
    assert sanitize('<p style="font-size:0.9em">visible</p>').hidden_text_detected is False
    assert sanitize('<p style="font-size:12px">visible</p>').hidden_text_detected is False
    assert sanitize('<p style="display:none">hidden</p>').hidden_text_detected is True
    assert sanitize('<p style="font-size:1px">tiny</p>').hidden_text_detected is True
    assert sanitize('<p style="max-height:0;overflow:hidden">x</p>').hidden_text_detected is True
    assert sanitize('<p style="text-indent:-999px">x</p>').hidden_text_detected is True


def test_risky_attachment_uses_filenames_not_body():
    body_only = Message(id="a", source="email", sender="a@b.com", ts=None, raw_text="download setup.exe now")
    assert TrustReason.RISKY_ATTACHMENT not in compute_signals(body_only, sanitize(body_only.raw_text))[1]

    attached = Message(
        id="b", source="email", sender="a@b.com", ts=None, raw_text="see attached", attachments=["payload.exe"]
    )
    assert TrustReason.RISKY_ATTACHMENT in compute_signals(attached, sanitize(attached.raw_text))[1]


def test_display_name_spoof_uses_brand_map():
    spoof = Message(id="c", source="email", sender='"Google Support" <x@evil.test>', ts=None, raw_text="hi")
    assert TrustReason.DISPLAY_NAME_SPOOF in compute_signals(spoof, sanitize(spoof.raw_text))[1]

    generic = Message(id="d", source="email", sender='"Support Team" <x@evil.test>', ts=None, raw_text="hi")
    assert TrustReason.DISPLAY_NAME_SPOOF not in compute_signals(generic, sanitize(generic.raw_text))[1]


def test_whatsapp_strips_direction_marks_and_detects_day_first(tmp_path):
    path = tmp_path / "chat.txt"
    path.write_text(
        "\u200e13/1/24, 9:41 AM - Alice: first\n"
        "\u200e14/1/24, 9:42 AM - Alice: second\n",
        encoding="utf-8",
    )
    messages = parse_whatsapp(path)
    assert len(messages) == 2
    assert messages[0].sender == "Alice"
    assert messages[0].ts.day == 13
    assert messages[1].ts.day == 14


def test_whatsapp_identical_messages_get_distinct_ids(tmp_path):
    path = tmp_path / "chat.txt"
    path.write_text(
        "1/1/24, 1:00 PM - Bob: ok\n"
        "1/1/24, 1:01 PM - Bob: ok\n",
        encoding="utf-8",
    )
    messages = parse_whatsapp(path)
    assert len(messages) == 2
    assert messages[0].id != messages[1].id


def test_input_cap_flags_truncation():
    sentences = ["a" * 100, "b" * 100, "c" * 100]
    kept, truncated = cap_sentences(sentences, max_chars=250)
    assert truncated is True
    assert kept == sentences[:2]

    kept_all, truncated_all = cap_sentences(sentences, max_chars=10_000)
    assert truncated_all is False
    assert kept_all == sentences


def test_store_cache_key_includes_model_and_hashes(store):
    message = Message(id="cache-1", source="email", sender="a@b.com", ts=None, raw_text="hello")
    store.save_message(
        message=message,
        extraction=None,
        urgency=None,
        deadline=None,
        amount=None,
        section="fyi",
        unparsed=True,
        disputed=False,
        model_tag="gemma3:4b",
        schema_hash="s1",
        prompt_hash="p1",
    )
    assert store.is_cached("cache-1", "gemma3:4b", "s1", "p1") is True
    assert store.is_cached("cache-1", "other-model", "s1", "p1") is False
    assert store.is_cached("cache-1", "gemma3:4b", "s2", "p1") is False
