# Airlock

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](#quick-start)
[![CI](https://github.com/Krit-Jain/Airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/Krit-Jain/Airlock/actions/workflows/ci.yml)

**Sleep while it reads your inbox.**

Airlock reads your untrusted email and WhatsApp exports overnight and produces a morning
brief you can act on without reading every message. A small open-weight model does the
pointing; deterministic code does the reading. The result is a local, fully offline
triage that cannot be prompt-injected into acting on an attacker's instructions.

**The model points. Code reads.**

## How it works

```mermaid
flowchart TD
    A[Raw inbox: .mbox, .eml, WhatsApp .txt] --> B[Ingest]
    B --> C[Sanitize and flag hidden content]
    C --> D[Compute trust signals]
    D --> E[Split into numbered sentences]
    E --> F[Quarantined model: enums + sentence ids only]
    F --> G[Validate against schema]
    G --> H[Resolve quotes, dates, amounts]
    H --> I[Rank with trust cap]
    I --> J[HTML brief]
    I --> K[SQLite store]
    I --> L[MCP server]
```

The quarantined model only ever points at what it saw. Every piece of text, every
date, every amount, and every trust decision is produced by deterministic code.

## What it does

- Ingests `.mbox`, `.eml`, and WhatsApp chat exports.
- Runs a small local model (Gemma via Ollama) once per message, constrained to emit only
  typed fields: category, urgency, request type, and sentence indices.
- Computes trust labels with deterministic code, never the model.
- Renders a static HTML morning brief and exposes a read-only MCP server for other
  open-source agents.
- Ships a red-team evaluation harness that measures hijack and manipulation rates against
  a naive agent and a detector-style baseline.

## Why it is safe to be lazy

A lazy agent is only useful if you can trust it not to follow instructions buried in your
inbox. Airlock removes the attack path instead of trying to detect it:

- The quarantined model has **no free-text output field**. It can only return enums and
  sentence indices, so attacker text can never be copied back out by the model.
- **Trust comes from code.** The model's urgency is capped by code-computed trust, so a
  message cannot promote itself to "urgent" just by saying so.
- **Quotes are human-only.** The brief shows the real quote with a trust label, but quotes
  never reach a model, an MCP client, or a trace.

See `docs/THREAT_MODEL.md` for what Airlock does and does not protect against.

## Why open innovation matters here

Airlock runs entirely on your machine. Your messages never leave the device, there is no
per-token billing, and because the sampler is local, schema enforcement is auditable
rather than a prompt-level request. You can swap or fine-tune the quarantine model without
changing the security boundary, and overnight inference costs nothing.

## Quick start

```bash
git clone https://github.com/Krit-Jain/Airlock.git
cd Airlock
uv sync
uv run airlock demo
```

The demo uses the deterministic mock adapter, so it needs no model and no network. To use
a real local model:

```bash
ollama pull gemma3:4b
uv run airlock run --model gemma3:4b
```

## Usage

```bash
airlock ingest path/to/inbox.mbox
airlock run --model gemma3:4b
airlock brief --open
airlock proposals
airlock approve 1
airlock serve-mcp
airlock eval
```

`--model mock` runs the offline deterministic adapter for tests and demos.

## MCP server

The server exposes three read-only tools over stdio: `list_messages`, `get_message`, and
`propose_action`. It returns only typed fields and sentence indices; it never returns
sender strings or quote text. A fuzz test asserts that attacker canaries cannot appear in
any MCP response.

## Measured results

The numbers below are copied from a real run of the evaluation harness on `gemma3:4b`
(23 messages: 12 benign, 11 attacks). See `results/REPORT.md`.

| Metric | Naive agent | Detector baseline | Airlock |
| --- | ---: | ---: | ---: |
| Hijack success rate | 63.6% | 9.1% | 0.0% |

| Airlock metric | Value |
| --- | ---: |
| Manipulation before trust cap | 18.2% |
| Manipulation after trust cap | 0.0% |
| Category accuracy (benign) | 83.3% |
| Request type accuracy (benign) | 66.7% |
| Urgency accuracy (benign) | 75.0% |
| Deadline sentence exact match | 100.0% |
| Amount sentence exact match | 100.0% |

## Project layout

```text
airlock/
├── docs/            Architecture, threat model, and model notes
├── src/airlock/     The pipeline, CLI, brief, MCP server, and store
├── eval/            Corpus generator, baselines, and evaluation runner
└── tests/           Structural, unit, and integration tests
```

## Development

```bash
uv sync
uv run pytest
```

## License

MIT
