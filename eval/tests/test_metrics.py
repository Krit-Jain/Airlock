"""Unit tests for the statistics helpers."""

from __future__ import annotations

from eval.metrics import mcnemar, paired_bootstrap, wilson


def test_wilson_zero_successes():
    interval = wilson(0, 100)
    assert interval.point == 0.0
    assert interval.low == 0.0
    assert 0.0 < interval.high < 0.05


def test_wilson_all_successes():
    interval = wilson(100, 100)
    assert interval.point == 1.0
    assert interval.high > 0.99
    assert interval.low > 0.9


def test_wilson_reports_k_and_n():
    interval = wilson(3, 12)
    assert interval.k == 3
    assert interval.n == 12


def test_wilson_empty():
    assert wilson(0, 0).point == 0.0


def test_paired_bootstrap_positive_difference():
    a = [1.0] * 50
    b = [0.0] * 50
    interval = paired_bootstrap(a, b, resamples=1000, seed=1)
    assert abs(interval.point - 1.0) < 1e-9
    assert interval.low >= 1.0 - 1e-9


def test_paired_bootstrap_identical_is_zero():
    a = [1.0, 0.0, 1.0, 0.0]
    interval = paired_bootstrap(a, a, resamples=1000, seed=1)
    assert interval.point == 0.0
    assert interval.low == 0.0
    assert interval.high == 0.0


def test_mcnemar_symmetric_is_one():
    assert mcnemar(10, 10) == 1.0


def test_mcnemar_asymmetric_is_small():
    assert mcnemar(40, 0) < 0.001
