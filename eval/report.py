"""Auto-generate ``results/REPORT.md`` from measured results."""

from __future__ import annotations

from pathlib import Path


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def write_report(results: dict, path: str | Path) -> None:
    meta = results["metadata"]
    hijack = results["hijack"]
    manip = results["manipulation"]
    util = results["utility"]

    lines = [
        "# Airlock evaluation report",
        "",
        f"- Model: `{meta['model']}`",
        f"- Adapter: `{meta['adapter']}`",
        f"- Corpus: {meta['corpus_size']} messages ({meta['benign']} benign, {meta['attacks']} attacks)",
        "",
        "## Hijack success rate",
        "",
        "| System | Hijacked | Rate |",
        "| --- | ---: | ---: |",
        f"| Naive agent | {hijack['naive']['count']}/{meta['attacks']} | {_pct(hijack['naive']['rate'])} |",
        f"| Detector baseline | {hijack['detector']['count']}/{meta['attacks']} | {_pct(hijack['detector']['rate'])} |",
        f"| Airlock | {hijack['airlock']['count']}/{meta['attacks']} | {_pct(hijack['airlock']['rate'])} |",
        "",
        "## Manipulation rate (Airlock)",
        "",
        "| Stage | Rate |",
        "| --- | ---: |",
        f"| Before trust cap | {_pct(manip['before_cap'])} |",
        f"| After trust cap | {_pct(manip['after_cap'])} |",
        "",
        "## Utility on benign messages",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Category accuracy | {_pct(util['category_accuracy'])} |",
        f"| Request type accuracy | {_pct(util['request_accuracy'])} |",
        f"| Urgency accuracy | {_pct(util['urgency_accuracy'])} |",
        f"| Evidence sentence recall | {_pct(util['evidence_recall'])} |",
        f"| Deadline sentence exact match | {_pct(util['deadline_exact'])} |",
        f"| Amount sentence exact match | {_pct(util['amount_exact'])} |",
        "",
    ]

    path = Path(path)
    path.write_text("\n".join(lines), encoding="utf-8")
