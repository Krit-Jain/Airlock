# Airlock

Airlock reads your untrusted email and WhatsApp exports overnight and produces a
morning brief you can trust. A small open-weight model does the pointing; deterministic
code does the reading. The result is a local, fully offline triage that cannot be
prompt-injected into acting on an attacker's instructions.

**The model points. Code reads.**

## What it does

- Ingests `.mbox`, `.eml`, and WhatsApp chat exports.
- Runs a small local model (Gemma via Ollama) once per message, constrained to emit
  only typed fields: category, urgency, request type, and sentence IDs.
- Computes trust labels with deterministic code, never the model.
- Renders a static HTML morning brief and exposes a read-only MCP server for other
  open-source agents.
- Ships a red-team evaluation harness that measures hijack and manipulation rates
  against a naive agent and a detector-style baseline.

## Why open innovation matters here

Airlock runs entirely on your machine. Your messages never leave the device, there is
no per-token billing, and because the sampler is local, schema enforcement is auditable
rather than a prompt-level request. You can swap or fine-tune the quarantine model
without changing the security boundary.

## Status

Under active development. Core pipeline, evaluation harness, and MCP server are being
built inside the Hacktoberfest 2026 contest window.

## License

MIT
