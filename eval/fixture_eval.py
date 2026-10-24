"""Model-free fixture evaluation.

Measures the deterministic trust and sanitizer layers on the header, HTML, and Unicode
fixtures: detection on spoofs and hidden text, false-suspicious and false-hidden rates on
legitimate mail, and sanitizer false-deletion on legitimate CSS.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from airlock.ingest.mbox import parse_eml
from airlock.models import TrustLabel
from airlock.sanitize import sanitize, strip_invisible
from airlock.signals import SignalConfig, compute_signals

from .metrics import wilson

FIXTURES = Path(__file__).parent / "fixtures"


def _rate(k: int, n: int) -> dict:
    interval = wilson(k, n)
    return {"k": k, "n": n, "point": interval.point, "low": interval.low, "high": interval.high}


def _headers_eval() -> dict:
    directory = FIXTURES / "headers"
    labels = json.loads((directory / "labels.json").read_text(encoding="utf-8"))

    spoof_total = spoof_detected = 0
    legit_total = legit_false = 0
    by_category: dict[str, list[int]] = defaultdict(lambda: [0, 0])

    for name, meta in labels.items():
        message = parse_eml(directory / name)[0]
        label, _reasons = compute_signals(message, sanitize(message.raw_text), SignalConfig.empty())
        suspicious = label == TrustLabel.SUSPICIOUS
        if meta["expect"] == "suspicious":
            spoof_total += 1
            spoof_detected += int(suspicious)
            by_category[meta["category"]][0] += 1
            by_category[meta["category"]][1] += int(suspicious)
        else:
            legit_total += 1
            legit_false += int(suspicious)

    return {
        "spoof_detection": _rate(spoof_detected, spoof_total),
        "legit_false_suspicious": _rate(legit_false, legit_total),
        "by_category": {cat: _rate(v[1], v[0]) for cat, v in sorted(by_category.items())},
    }


def _html_eval() -> dict:
    directory = FIXTURES / "html"
    labels = json.loads((directory / "labels.json").read_text(encoding="utf-8"))

    hidden_total = hidden_found = 0
    legit_total = legit_false = 0
    legit_content_kept = legit_content_total = 0

    for name, meta in labels.items():
        html = (directory / name).read_text(encoding="utf-8")
        result = sanitize(html)
        if meta["expect_hidden"]:
            hidden_total += 1
            hidden_found += int(result.hidden_text_detected)
        else:
            legit_total += 1
            legit_false += int(result.hidden_text_detected)
            legit_content_total += 1
            legit_content_kept += int("Footer text" in result.text)

    return {
        "hidden_detection": _rate(hidden_found, hidden_total),
        "legit_false_hidden": _rate(legit_false, legit_total),
        "legit_content_preserved": _rate(legit_content_kept, legit_content_total),
    }


def _unicode_eval() -> dict:
    directory = FIXTURES / "unicode"
    labels = json.loads((directory / "labels.json").read_text(encoding="utf-8"))

    dangerous_total = dangerous_found = 0
    legit_total = legit_false = 0
    stripped_all = 0

    for name, meta in labels.items():
        text = (directory / name).read_text(encoding="utf-8")
        result = sanitize(text)
        if meta["expect_dangerous"]:
            dangerous_total += 1
            dangerous_found += int(result.invisible_unicode_detected)
            stripped_all += int(strip_invisible(text) == result.text)
        else:
            legit_total += 1
            legit_false += int(result.invisible_unicode_detected)

    return {
        "dangerous_detection": _rate(dangerous_found, dangerous_total),
        "dangerous_stripped": _rate(stripped_all, dangerous_total),
        "legit_false_dangerous": _rate(legit_false, legit_total),
    }


def run_fixture_eval(out_dir: str | Path = "results") -> dict:
    results = {"headers": _headers_eval(), "html": _html_eval(), "unicode": _unicode_eval()}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "fixtures.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


if __name__ == "__main__":
    print(json.dumps(run_fixture_eval(), indent=2))
