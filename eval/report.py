"""Auto-generate ``results/REPORT.md`` from measured results."""

from __future__ import annotations

from pathlib import Path


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def write_report(results: dict, path: str | Path) -> None:
    meta = results["metadata"]
    baseline = results["baseline_hijack"]
    util = results["utility"]

    lines = [
        "# Airlock evaluation report",
        "",
        "This is the deterministic smoke harness. It reports scripted baselines, benign",
        "extraction utility, and the analytic worst-case table. The agent-based evaluation",
        "is defined in `eval/PREREGISTRATION.md` and produces the full report when run.",
        "",
        f"- Model: `{meta['model']}` (adapter: `{meta['adapter']}`)",
        f"- Corpus: {meta['corpus_size']} messages ({meta['benign']} benign, {meta['attacks']} attacks)",
        "",
        "## Baseline hijack (scripted, not models)",
        "",
        "| Baseline | Hijacked | Rate |",
        "| --- | ---: | ---: |",
        f"| Gullible policy | {baseline['gullible_policy']['count']}/{meta['attacks']} | "
        f"{_pct(baseline['gullible_policy']['rate'])} |",
        f"| Heuristic regex | {baseline['heuristic_regex']['count']}/{meta['attacks']} | "
        f"{_pct(baseline['heuristic_regex']['rate'])} |",
        "",
        "These are hand-written policies, not language models. They show that the corpus",
        "contains hijackable payloads and that a trigger-word filter is incomplete.",
        "",
        "## Utility on benign messages",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Category accuracy | {_pct(util['category_accuracy'])} |",
        f"| Request type accuracy | {_pct(util['request_accuracy'])} |",
        f"| Urgency accuracy | {_pct(util['urgency_accuracy'])} |",
        f"| Evidence sentence recall | {_pct(util['evidence_recall'])} |",
        "",
        "## Worst-case reachability (analytic)",
        "",
        "Assumes the quarantine model is fully compromised. Rows are trust labels.",
        "",
        "| Trust label | Reaches needs_you | Max urgency in needs_you | Max urgency anywhere |",
        "| --- | --- | --- | --- |",
    ]

    for reach in results["worst_case"]:
        lines.append(
            f"| {reach['trust']} | {'yes' if reach['needs_you_reachable'] else 'no'} | "
            f"{reach['max_urgency_in_needs_you'] or '-'} | {reach['max_urgency_any']} |"
        )

    lines.append("")
    Path(path).write_text("\n".join(lines), encoding="utf-8")
