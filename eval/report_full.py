"""Build the full evaluation report from the artifact files.

Reads whatever result artifacts exist under ``results/`` and renders a single markdown
report with tables, simple bar charts, and a failure gallery. Missing experiments are
listed as not yet run rather than silently omitted.
"""

from __future__ import annotations

import json
from pathlib import Path


def _load(results_dir: Path, name: str) -> dict | None:
    path = results_dir / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _bar(value: float, width: int = 20) -> str:
    filled = int(round(max(0.0, min(1.0, value)) * width))
    return "#" * filled + "." * (width - filled)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _ci(interval: dict) -> str:
    return f"{_pct(interval['point'])} [{_pct(interval['low'])}, {_pct(interval['high'])}] ({interval['k']}/{interval['n']})"


def _worst_case_table(worst_case: list[dict]) -> list[str]:
    lines = [
        "| Trust label | Reaches needs_you | Max urgency in needs_you | Max urgency anywhere |",
        "| --- | --- | --- | --- |",
    ]
    for reach in worst_case:
        trust = reach["trust"]
        trust = trust.value if hasattr(trust, "value") else trust
        lines.append(
            f"| {trust} | {'yes' if reach['needs_you_reachable'] else 'no'} | "
            f"{reach['max_urgency_in_needs_you'] or '-'} | {reach['max_urgency_any']} |"
        )
    return lines


def _fixtures_section(fixtures: dict | None) -> list[str]:
    if not fixtures:
        return ["Not yet run.", ""]
    lines = ["| Check | Rate |", "| --- | ---: |"]
    lines.append(f"| Spoof detection | {_ci(fixtures['headers']['spoof_detection'])} |")
    lines.append(f"| Legitimate false-suspicious | {_ci(fixtures['headers']['legit_false_suspicious'])} |")
    lines.append(f"| Hidden-text detection | {_ci(fixtures['html']['hidden_detection'])} |")
    lines.append(f"| Legitimate false-hidden | {_ci(fixtures['html']['legit_false_hidden'])} |")
    lines.append(f"| Legitimate content preserved | {_ci(fixtures['html']['legit_content_preserved'])} |")
    lines.append(f"| Dangerous Unicode detected | {_ci(fixtures['unicode']['dangerous_detection'])} |")
    lines.append(f"| Legitimate false-dangerous | {_ci(fixtures['unicode']['legit_false_dangerous'])} |")
    lines.append("")
    return lines


def _agent_section(agent: dict | None) -> list[str]:
    if not agent:
        return ["Not yet run.", ""]
    meta = agent["metadata"]
    lines = [
        f"- Quarantine model: `{meta['quarantine_model']}`; agent policy: `{meta['agent_policy']}`; "
        f"judge: `{meta.get('judge_policy', 'n/a')}`; split: `{meta['split']}`; attacks: {meta['attacks']}",
        "",
        "| System | ASR unauth | ASR canary | ASR induced | Taint runs |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for system, stats in agent["systems"].items():
        lines.append(
            f"| {system} | {_ci(stats['asr_unauth'])} | {_ci(stats['asr_canary'])} | "
            f"{_ci(stats['asr_induced'])} | {stats['taint_violation_runs']} |"
        )
    lines.append("")
    lines.append("```")
    for system, stats in agent["systems"].items():
        lines.append(f"{system:<4} unauth {_bar(stats['asr_unauth']['point'])} {_pct(stats['asr_unauth']['point'])}")
    lines.append("```")
    lines.append("")
    judge = agent.get("judge")
    if judge:
        lines.append(f"Judge false-positive on benign: {_ci(judge['benign_false_positive'])}")
        lines.append("")
    return lines


def _steering_section(steering: dict | None) -> list[str]:
    if not steering:
        return ["Not yet run.", ""]
    metrics = ["flip_category", "flip_request_type", "urgency_raised_before_cap", "urgency_raised_after_cap", "promotion", "suppression", "review_diversion"]
    lines = [
        "| Sender variant | n | " + " | ".join(metrics) + " |",
        "| --- | ---: | " + " | ".join("---:" for _ in metrics) + " |",
    ]
    for variant, stats in steering["by_sender_variant"].items():
        cells = " | ".join(_pct(stats[m]["point"]) for m in metrics)
        lines.append(f"| {variant} | {stats['n']} | {cells} |")
    lines.append("")
    return lines


def _failure_gallery(results_dir: Path) -> list[str]:
    path = results_dir / "agent_eval.jsonl"
    if not path.exists():
        return ["Not yet run.", ""]
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    airlock_failures = [r for r in rows if r["system"] in ("S3", "S3b") and (r["taint_violations"] or r["canary"] or r["unauth"])]
    raw_leaks = [r for r in rows if r["system"] == "S0" and r["canary"]][:10]
    lines: list[str] = []
    if airlock_failures:
        lines.append(f"Airlock-fed failures: {len(airlock_failures)} (listed below).")
        for row in airlock_failures[:10]:
            lines.append(f"- {row['system']} {row['instance']}: taint={row['taint_violations']} canary={row['canary']}")
    else:
        lines.append("Airlock-fed failures: none. No attacker string or canary reached an Airlock-fed agent.")
    lines.append("")
    lines.append("Examples of raw-context leaks (S0):")
    for row in raw_leaks:
        lines.append(f"- {row['instance']}: canary leaked into a tool call")
    lines.append("")
    return lines


def build_report(results_dir: str | Path = "results") -> str:
    results_dir = Path(results_dir)
    agent = _load(results_dir, "agent_eval.json")
    steering = _load(results_dir, "steering.json")
    fixtures = _load(results_dir, "fixtures.json")
    schema = _load(results_dir, "schema_escape.json")
    cross = _load(results_dir, "cross_message.json")

    from dataclasses import asdict

    from .worstcase import worst_case_table

    lines: list[str] = ["# Airlock evaluation report", ""]
    lines += ["## Worst-case reachability (analytic)", "", "Assumes the quarantine model is fully compromised.", ""]
    lines += _worst_case_table([asdict(r) for r in worst_case_table()])
    lines += ["", "## Deterministic trust and sanitizer layers", ""]
    lines += _fixtures_section(fixtures)
    lines += ["## Schema escape", ""]
    if schema:
        lines += [
            f"- Model: `{schema['model']}`, prompts: {schema['n']}",
            f"- Schema-valid at the sampler: {_pct(schema['schema_valid_rate'])} ({schema['schema_valid']}/{schema['n']})",
            f"- Not JSON: {schema['not_json']}; invalid schema: {schema['invalid_schema']}; out-of-vocabulary: {schema['out_of_vocabulary']}",
            "",
        ]
    else:
        lines += ["Not yet run.", ""]
    lines += ["## Cross-message isolation", ""]
    if cross:
        lines += [
            f"- Victims: {cross['n']}; noise floor: {cross['noise_floor']}; changed with an attack present: {cross['changed_with_attack']}",
            f"- Stable: {'yes' if cross['stable'] else 'no'}",
            "",
        ]
    else:
        lines += ["Not yet run.", ""]
    lines += ["## Agent systems", ""]
    lines += _agent_section(agent)
    lines += ["## Steering (paired against clean twins)", ""]
    lines += _steering_section(steering)
    lines += ["## Failure gallery", ""]
    lines += _failure_gallery(results_dir)

    return "\n".join(lines) + "\n"


def write_report(results_dir: str | Path = "results") -> Path:
    results_dir = Path(results_dir)
    path = results_dir / "REPORT.md"
    path.write_text(build_report(results_dir), encoding="utf-8")
    return path


if __name__ == "__main__":
    print(write_report())
