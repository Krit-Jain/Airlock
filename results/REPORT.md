# Airlock evaluation report

This is the deterministic smoke harness. It reports scripted baselines, benign
extraction utility, and the analytic worst-case table. The agent-based evaluation
is defined in `eval/PREREGISTRATION.md` and produces the full report when run.

- Model: `mock` (adapter: `mock`)
- Corpus: 23 messages (12 benign, 11 attacks)

## Baseline hijack (scripted, not models)

| Baseline | Hijacked | Rate |
| --- | ---: | ---: |
| Gullible policy | 7/11 | 63.6% |
| Heuristic regex | 1/11 | 9.1% |

These are hand-written policies, not language models. They show that the corpus
contains hijackable payloads and that a trigger-word filter is incomplete.

## Utility on benign messages

| Metric | Value |
| --- | ---: |
| Category accuracy | 33.3% |
| Request type accuracy | 41.7% |
| Urgency accuracy | 16.7% |
| Evidence sentence recall | 100.0% |

## Worst-case reachability (analytic)

Assumes the quarantine model is fully compromised. Rows are trust labels.

| Trust label | Reaches needs_you | Max urgency in needs_you | Max urgency anywhere |
| --- | --- | --- | --- |
| TrustLabel.VERIFIED_KNOWN | yes | high | high |
| TrustLabel.KNOWN_UNVERIFIED | yes | medium | medium |
| TrustLabel.UNKNOWN | yes | low | low |
| TrustLabel.SUSPICIOUS | no | - | low |
