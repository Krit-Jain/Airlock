---
title: "Airlock: an overnight inbox brief that attacker text cannot reach"
published: false
tags: devchallenge, hf26challenge
---

*This is a submission for the [Hacktoberfest Open-Source AI Challenge Week 3: Slow and Steady](https://dev.to/challenges/hacktoberfest-week3-2026-10-19).*

## What I Built

Airlock reads your email and WhatsApp exports overnight and hands you a morning brief, so
you can skip the pile and act on the few messages that matter. The twist is that the
messages are untrusted: anyone can email you an instruction. Airlock lets you be lazy
without letting an inbox decide what your agent does.

The idea fits in one line: **the model points, code reads.** A small local model reads one
message at a time and may only emit closed enums and sentence indices. It never copies
attacker text back out. Deterministic code turns those indices into quotes, dates, amounts,
trust labels, and a ranking. The model that reads your inbox has no tools and no authority;
the code that acts cannot be prompt-injected.

It ships as a CLI, a static HTML brief, and a read-only MCP server that other agents can
query without ever receiving a sender string or a quote.

## Demo

```bash
git clone https://github.com/Krit-Jain/Airlock
cd Airlock
uv sync
uv run airlock demo
```

`airlock demo` runs a synthetic poisoned inbox through the full pipeline with a
deterministic offline adapter and opens the brief. To use the real model:

```bash
ollama pull gemma3:4b
uv run airlock ingest path/to/inbox.mbox
uv run airlock run --model gemma3:4b
uv run airlock brief --open
```

The brief has four sections: Needs you, Deadlines and amounts, Review carefully, and FYI.
Quotes are labeled untrusted and shown only to you; links are defanged to plain text. The
quarantine model has no free-text output field, so a message can tell you anything but
cannot make the model say anything. A generated example brief is committed at
`docs/demo-brief.html`, and a narrated walkthrough is at `docs/demo.mp4` (upload it to DEV
when publishing).

## Code

Repository: https://github.com/Krit-Jain/Airlock (MIT).

The parts worth reading first:

- `src/airlock/schema.py`: the enum-only extraction schema. A test walks the generated JSON
  schema and fails the build if any string field lacks an enum.
- `src/airlock/signals.py`: deterministic trust from headers, domains, hidden text, and
  contacts.
- `src/airlock/taint.py` and `gate.py`: values carry an origin, and sinks refuse
  untrusted-derived values without a human approval token.
- `eval/`: the harness, corpus, systems, and the pre-registered protocol.

## How I Built It

I used open-weight models end to end. The quarantine extractor runs `gemma3:4b` through
Ollama with schema-constrained decoding, temperature zero, one isolated call per message,
and reasoning disabled. The evaluation is a paired corpus of 232 test-split attacks built
from clean messages plus a payload, with unique canaries, five sender variants, and several
encodings.

The evaluation asks whether the design does what it claims, and it is willing to fail:

- **Deterministic layers.** On 65 header fixtures, 60 HTML fixtures, and 20 Unicode
  fixtures: 100% spoof detection with 0% false-suspicious on 40 legitimate senders, 100%
  hidden-text detection with 0% false-hidden on 30 legitimate-CSS emails, and dangerous
  Unicode detected and stripped with no false positives.
- **Schema escape.** Across 200 adversarial prompts, the sampler returned schema-valid JSON
  200 times, with no out-of-vocabulary token. The check parses raw model output before
  validation and fails if the sampler lets a payload through.
- **Cross-message isolation.** Fifty victim messages produced byte-identical records with
  and without an attack message present.
- **Worst case.** Assuming a fully compromised extractor, an unknown sender can reach the
  "Needs you" section but cannot reach high urgency; only a genuine known contact can.

The headline result is the mechanism check. Across 232 audited attacks, **no attacker
string and no canary ever reached an Airlock-fed agent**, even when `forward_email`,
`send_email`, and `fetch_url` were exposed as tools.

I also report what did not go as hoped. The real `gemma3:4b` agent was rarely hijacked in a
flat context (0.4% unauthorized calls, 1.3% canary leaks), so the detectors and prompt
defenses had little left to reduce. That is the model's behavior, not a broken harness: a
deterministic gullible oracle leaks the canary, proving the audit can fail. And steering
remains real: payloads changed the action taken on a message 25-44% of the time, and a
compromised known contact can be promoted past the trust cap. Airlock stops hijacking, not
persuasion.

## Why Does Open Innovation Matter?

This project exists because the model runs on your machine.

- **Your mail never leaves the device.** There is no API call, no account, no per-token
  bill. The brief is generated from a local SQLite store.
- **The security boundary is auditable.** Because the sampler is local, the schema passed
  to it is the schema you can read and test. That is not true when the constraint lives
  behind someone else's API.
- **You can swap the model.** The quarantine model is a configuration detail. Change the
  tag, keep the boundary.
- **It costs nothing to run overnight.** A 4 GB laptop runs the full pipeline and the
  evaluation.

A closed API could give me structured output. It could not give me a boundary I can read,
test, and replace without changing the trust model.

## The Lazy Payoff

The point is to move the chore, not to watch it. You run one command before bed and read a
short brief in the morning: a handful of things that need you, the deadlines and amounts,
and a clearly separated pile to review. Everything else is filed or ignored. The trust
labels mean you can skim the safe items and slow down only where the code says the sender
is unverified or the content is hidden.

## Limitations

- Single labeler for the corpus rubric, and a synthetic corpus rather than real inbox data.
- Small open-weight models only; the numbers describe this class of model.
- Typed fields are attacker-influenced even when attacker text never reaches an LLM, which
  is why the steering numbers are reported.
- Encoded payloads (base64, tag-block) evade literal text checks, so the taint audit
  under-counts them.

## Prize Categories

- Best Use of Gemma: the quarantine extractor is `gemma3:4b` run locally through Ollama
  with schema-constrained decoding.
