"""Self-validation test for the full report builder."""

from __future__ import annotations

from eval.report_full import build_report


def test_report_contains_all_sections():
    text = build_report()
    for heading in (
        "Worst-case reachability",
        "Deterministic trust and sanitizer layers",
        "Schema escape",
        "Cross-message isolation",
        "Agent systems",
        "Steering",
        "Failure gallery",
    ):
        assert heading in text


def test_report_renders_trust_labels_as_values():
    text = build_report()
    assert "verified_known" in text
    assert "TrustLabel." not in text
