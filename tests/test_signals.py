from airlock.models import Message, TrustLabel, TrustReason
from airlock.sanitize import sanitize
from airlock.signals import SignalConfig, compute_signals


def _message(raw, sender="Alice <alice@example.com>", headers=None):
    return Message(id="x", source="email", sender=sender, ts=None, raw_text=raw, headers=headers or {})


def test_hidden_text_marks_suspicious() -> None:
    msg = _message('<div style="display:none">x</div>visible')
    label, reasons = compute_signals(msg, sanitize(msg.raw_text))
    assert label == TrustLabel.SUSPICIOUS
    assert TrustReason.HIDDEN_TEXT in reasons


def test_known_contact_with_passing_auth() -> None:
    msg = _message("hello", headers={"Authentication-Results": "spf=pass dkim=pass dmarc=pass"})
    config = SignalConfig(known_contacts={"alice@example.com"})
    label, _ = compute_signals(msg, sanitize(msg.raw_text), config)
    assert label == TrustLabel.VERIFIED_KNOWN


def test_unknown_sender_is_unknown() -> None:
    msg = _message("hello")
    label, reasons = compute_signals(msg, sanitize(msg.raw_text))
    assert label == TrustLabel.UNKNOWN
    assert TrustReason.FIRST_TIME_SENDER in reasons


def test_whatsapp_is_never_verified() -> None:
    msg = Message(id="x", source="whatsapp", sender="Mom", ts=None, raw_text="hi", headers={})
    config = SignalConfig(known_contacts={"mom"})
    label, reasons = compute_signals(msg, sanitize(msg.raw_text), config)
    assert label == TrustLabel.KNOWN_UNVERIFIED
    assert TrustReason.UNVERIFIED_CHAT in reasons
