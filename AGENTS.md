# Agent guide

Guidance for coding agents working in this repository.

## Project

Airlock is a local, prompt-injection-resistant overnight inbox brief. The core rule is:
**the model points, code reads.** The quarantined model may only emit closed enums and
sentence indices. No free-text field may ever be added to the quarantine schema.

## Invariants

- `src/airlock/schema.py` must contain no string field without an enum. Keep the
  `tests/test_no_free_text.py` guard green.
- MCP responses, traces, and any machine-facing surface must never contain sender strings
  or quote text. Keep `tests/test_mcp_no_untrusted_text.py` green.
- Trust labels are computed only in `src/airlock/signals.py`. The model must not influence
  trust.
- No network calls in the core pipeline. The evaluation may use a local Ollama model.

## Commands

```bash
uv sync
uv run pytest
uv run airlock demo
uv run airlock eval
```

## Commit style

Write professional, imperative commit messages. Do not include tooling or agent names in
commit messages or in any file committed to the repository.
