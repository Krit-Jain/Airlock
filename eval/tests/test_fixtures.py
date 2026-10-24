"""Self-validation tests for the model-free fixture suites."""

from __future__ import annotations

from airlock.sanitize import sanitize
from airlock.signals import SignalConfig, compute_signals
from airlock.models import Message, TrustLabel, TrustReason

from eval.fixture_eval import run_fixture_eval


def test_fixture_suites_meet_minimum_sizes():
    result = run_fixture_eval()
    assert result["headers"]["spoof_detection"]["n"] >= 25
    assert result["headers"]["legit_false_suspicious"]["n"] >= 40
    assert result["html"]["hidden_detection"]["n"] >= 30
    assert result["html"]["legit_false_hidden"]["n"] >= 30
    assert result["unicode"]["dangerous_detection"]["n"] >= 8


def test_deterministic_layers_detect_spoofs_and_spare_legit():
    result = run_fixture_eval()
    assert result["headers"]["spoof_detection"]["point"] > 0.8
    assert result["headers"]["legit_false_suspicious"]["point"] < 0.1
    assert result["html"]["hidden_detection"]["point"] > 0.8
    assert result["html"]["legit_false_hidden"]["point"] == 0.0
    assert result["html"]["legit_content_preserved"]["point"] > 0.9
    assert result["unicode"]["dangerous_detection"]["point"] > 0.8
    assert result["unicode"]["legit_false_dangerous"]["point"] == 0.0


def _message(sender, headers=None):
    return Message(id="x", source="email", sender=sender, ts=None, raw_text="hello", headers=headers or {})


def test_reply_to_mismatch_is_suspicious():
    msg = _message("Billing <billing@yourbank.example>", {"Reply-To": ["collect@evil.test"]})
    label, reasons = compute_signals(msg, sanitize(msg.raw_text))
    assert label == TrustLabel.SUSPICIOUS
    assert TrustReason.DOMAIN_MISMATCH in reasons


def test_return_path_mismatch_is_not_suspicious():
    msg = _message("News <news@acme.example>", {"Return-Path": ["<bounce@esp.example>"]})
    label, reasons = compute_signals(msg, sanitize(msg.raw_text), SignalConfig.empty())
    assert label != TrustLabel.SUSPICIOUS
    assert TrustReason.DOMAIN_MISMATCH in reasons
