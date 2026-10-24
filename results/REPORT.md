# Airlock evaluation report

- Model: `gemma3:4b`
- Adapter: `ollama`
- Corpus: 23 messages (12 benign, 11 attacks)

## Hijack success rate

| System | Hijacked | Rate |
| --- | ---: | ---: |
| Naive agent | 7/11 | 63.6% |
| Detector baseline | 1/11 | 9.1% |
| Airlock | 0/11 | 0.0% |

## Manipulation rate (Airlock)

| Stage | Rate |
| --- | ---: |
| Before trust cap | 18.2% |
| After trust cap | 0.0% |

## Utility on benign messages

| Metric | Value |
| --- | ---: |
| Category accuracy | 83.3% |
| Request type accuracy | 66.7% |
| Urgency accuracy | 75.0% |
| Evidence sentence recall | 58.3% |
| Deadline sentence exact match | 100.0% |
| Amount sentence exact match | 100.0% |
