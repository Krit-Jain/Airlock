"""Self-validation tests for the paired steering metrics."""

from __future__ import annotations

from airlock.extractor import MockAdapter

from eval.corpus.attack_gen import generate_attacks
from eval.steering import _METRICS, run_steering_eval, steering_flags


def test_steering_flags_have_all_metrics():
    attack = generate_attacks(per_cell=1)[0]
    flags = steering_flags(attack, attack["twin"], MockAdapter())
    for metric in _METRICS:
        assert metric in flags


def test_steering_eval_reports_by_sender_variant(tmp_path):
    summary = run_steering_eval(limit=8, out_dir=tmp_path)
    assert summary["metadata"]["attacks"] == 8
    assert summary["by_sender_variant"]
    for stats in summary["by_sender_variant"].values():
        assert stats["n"] > 0
        for metric in _METRICS:
            assert "point" in stats[metric]
