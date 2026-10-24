"""Statistical helpers for the evaluation.

Every proportion is reported as k/n with a Wilson 95% confidence interval. Differences
between systems on the same instances use a paired bootstrap.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from math import sqrt


@dataclass
class Interval:
    point: float
    low: float
    high: float
    k: int
    n: int


def wilson(k: int, n: int, z: float = 1.96) -> Interval:
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return Interval(0.0, 0.0, 0.0, k, n)
    p = k / n
    d = 1 + z * z / n
    center = (p + z * z / (2 * n)) / d
    half = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return Interval(p, max(0.0, center - half), min(1.0, center + half), k, n)


def paired_bootstrap(
    a: list[float],
    b: list[float],
    resamples: int = 10_000,
    seed: int = 0,
    z: float = 1.96,
) -> Interval:
    """Mean(a) - Mean(b) over paired observations, with a bootstrap CI.

    ``a`` and ``b`` must be aligned by instance.
    """
    if len(a) != len(b):
        raise ValueError("paired_bootstrap requires equal-length inputs")
    n = len(a)
    if n == 0:
        return Interval(0.0, 0.0, 0.0, 0, 0)

    deltas = [x - y for x, y in zip(a, b)]
    point = sum(deltas) / n

    rng = random.Random(seed)
    means: list[float] = []
    for _ in range(resamples):
        total = 0.0
        for _ in range(n):
            total += deltas[rng.randrange(n)]
        means.append(total / n)
    means.sort()
    lo = means[int(0.025 * len(means))]
    hi = means[int(0.975 * len(means))]
    return Interval(point, lo, hi, 0, n)


def mcnemar(b: int, c: int) -> float:
    """Exact-ish McNemar p-value for paired binary outcomes.

    ``b`` = instances where only system A succeeded, ``c`` = only system B.
    Uses the chi-square approximation with continuity correction.
    """
    if b + c == 0 or b == c:
        return 1.0
    chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    # Survival function of chi-square with 1 df at chi2 is erfc(sqrt(chi2/2)).
    from math import erfc

    return erfc(sqrt(chi2 / 2))
