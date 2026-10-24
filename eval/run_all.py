"""Run every experiment and write the report.

This is the one command the overnight batch uses. Every expensive step is cached, so
re-running after an interruption resumes rather than restarting. Use ``limit`` for a smoke
run and ``skip`` to run individual stages.
"""

from __future__ import annotations

import json
from pathlib import Path

from airlock.extractor import MockAdapter, OllamaAdapter

from .calibration import run_calibration
from .fixture_eval import run_fixture_eval
from .property_tests import run_cross_message_test
from .report_full import write_report
from .run_agent_eval import run_agent_eval
from .schema_escape import run_schema_escape
from .steering import run_steering_eval

STAGES = ("calibration", "fixtures", "schema", "cross", "agent", "steering")


def run_all(
    quarantine_model: str = "gemma3:4b",
    agent_model: str = "gemma3:4b",
    agent_policy: str = "ollama",
    judge_policy: str = "regex",
    limit: int | None = None,
    split: str = "test",
    out_dir: str | Path = "results",
    cache_dir: str | Path = "results/cache",
    skip: tuple[str, ...] = (),
    progress: bool = True,
) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ran: list[str] = []

    if "calibration" not in skip and agent_policy != "gullible":
        print("[1/6] calibration", flush=True)
        run_calibration(agent_model=agent_model, split="dev", out_dir=out)
        ran.append("calibration")

    if "fixtures" not in skip:
        print("[2/6] fixtures", flush=True)
        run_fixture_eval(out_dir=out)
        ran.append("fixtures")

    if "schema" not in skip:
        print("[3/6] schema escape", flush=True)
        schema_adapter = MockAdapter() if quarantine_model == "mock" else OllamaAdapter(model=quarantine_model)
        run_schema_escape(schema_adapter, n=50 if limit else 200, out_dir=out)
        ran.append("schema")

    if "cross" not in skip:
        print("[4/6] cross-message", flush=True)
        run_cross_message_test(n=limit or 50, quarantine_model=quarantine_model, out_dir=out)
        ran.append("cross")

    if "agent" not in skip:
        print("[5/6] agent systems", flush=True)
        run_agent_eval(
            quarantine_model=quarantine_model,
            agent_policy=agent_policy,
            agent_model=agent_model,
            judge_policy=judge_policy,
            limit=limit,
            split=split,
            out_dir=out,
            cache_dir=cache_dir,
            progress=progress,
        )
        ran.append("agent")

    if "steering" not in skip:
        print("[6/6] steering", flush=True)
        run_steering_eval(quarantine_model=quarantine_model, limit=limit, split=split, out_dir=out)
        ran.append("steering")

    report = write_report(out)
    return {"ran": ran, "report": str(report)}


if __name__ == "__main__":
    print(json.dumps(run_all(), indent=2))
