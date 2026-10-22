# Architecture

Airlock's core idea is a single sentence: **the model points, code reads.**

A small local model reads one message at a time and may only emit a typed record. All
textual work — quotes, dates, amounts, trust, ranking, rendering — is done by
deterministic code that cannot be prompt-injected.

## Pipeline

```text
raw inbox (.mbox, .eml, WhatsApp .txt)
        |
   [ingest]    -> Message{id, source, sender, ts, raw_text, headers}
        |
   [sanitize]  NFKC, strip zero-width/bidi/tag chars, HTML to text, drop hidden elements
        |       (hidden content is detected and flagged as a trust signal)
   [signals]   code-only trust features -> TrustLabel
        |
   [segment]   split into numbered sentences S0..Sn
        |
   QUARANTINE  one Ollama call per message, no tools, no history, temperature 0,
        |       schema-constrained decoding -> Extraction (enums + sentence ids only)
   [validate]  Pydantic extra=forbid + sentence-index range check -> else "unparsed"
   [resolve]   code: sentence ids -> quotes; dateparser/regex -> dates and amounts
   [rank]      code: urgency capped by trust; suspicious/unparsed/disputed -> review
        |
   +-> brief.html   (human only; quotes escaped, links defanged)
   +-> SQLite       (typed records, keyed by content hash, resumable)
   +-> MCP server   (read-only; typed fields and indices, never quote text)
```

There is no LLM on the privileged side. That is intentional: fewer moving parts and a
stronger, auditable boundary.

## The quarantine schema

The only shape a quarantined model may produce is defined in
`src/airlock/schema.py`. It contains closed enums for category, urgency, and request
type, a boolean, and bounded sentence indices. A test walks the generated JSON schema
and fails the build if any string field lacks an enum.

## Trust is code

Trust labels come only from `src/airlock/signals.py`: authentication headers, domain
mismatches, display-name spoofing, hidden text, invisible Unicode, link mismatches,
risky attachments, and known contacts. The model's urgency is capped by trust in
`src/airlock/rank.py`, so an attacker cannot promote an untrusted sender.

## Capability gate

Side-effecting functions are sinks in `src/airlock/gate.py`. Values carry an origin via
`src/airlock/taint.py`; values derived from untrusted text require a human approval
token before reaching a sink. The agent and MCP clients cannot self-approve.
