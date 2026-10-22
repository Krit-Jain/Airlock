# Model notes

## Chosen model

- **Model:** `gemma3:4b`
- **Size:** 3.4 GB (Q4 quantized)
- **Role:** the quarantined model that reads each message and emits the extraction schema.

## Hardware

- CPU: Intel UHD Graphics (integrated)
- GPU: NVIDIA GeForce RTX 4050 Laptop GPU (4 GB VRAM)
- RAM: 15.6 GB

`num_ctx` is set to 4096, appropriate for short per-message calls. The project is a
slow-and-steady overnight tool, so per-message latency is acceptable as long as it does
not crash.

## Verification findings

- Ollama `0.40.8` responds on `localhost:11434`.
- `gemma3:4b` accepts a JSON schema in the `format` parameter with enums, bounded
  integer arrays, and `additionalProperties: false`.
- Reasoning output is suppressed with `think: false`; only the final message content is
  used.
- The schema-enforcement integration tests pass against the real model: an adversarial
  prompt does not escape the schema.

## Swapping the model

The model is pluggable through `src/airlock/extractor.py`. Set `--model <tag>` on the
CLI or replace the adapter to use a different open-weight model without changing the
security boundary.
