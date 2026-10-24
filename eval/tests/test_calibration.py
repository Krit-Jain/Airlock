"""Self-validation tests for the calibration gate."""

from __future__ import annotations

from eval.calibration import _f1, run_calibration
from eval.systems import NullPolicy


def test_f1_perfect_and_zero():
    assert _f1(10, 0, 0)[2] == 1.0
    assert _f1(0, 0, 10)[2] == 0.0
    assert _f1(0, 0, 0)[2] == 0.0


def test_null_policy_fails_the_gate(tmp_path):
    result = run_calibration(policy=NullPolicy(), out_dir=tmp_path)
    assert result["gate_passed"] is False
    assert result["task_success"]["f1"] == 0.0
    assert result["batches"] > 0
