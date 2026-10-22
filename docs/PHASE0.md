# Phase 0 verification

Pre-build checks for the quarantined model and local toolchain.

## Findings

1. **Ollama version and model.** Ollama `0.40.8` is installed and running on
   `localhost:11434`. `gemma3:4b` (3.4 GB) was pulled and selected. See `MODELS.md`.
2. **Structured outputs.** Confirmed. `gemma3:4b` returns schema-valid JSON when the
   schema is passed through the `format` parameter. The schema includes enums, bounded
   integer arrays, and `additionalProperties: false`. `tests/test_schema_enforcement.py`
   passes against the real model.
3. **Thinking mode.** Disabled with `think: false`. Only `message.content` is used.
4. **Tool calling for the naive baseline.** The naive-agent baseline uses a
   deterministic gullible policy rather than a second model, so no tool-calling model is
   required for reproducibility.
5. **Tracing.** `sentry-sdk` is wired through `src/airlock/tracing.py`. Spans carry
   hashes, enums, and latency only; message text and reasoning are never recorded.
6. **Hardware.** 15.6 GB RAM, RTX 4050 (4 GB VRAM). `num_ctx` set to 4096. See
   `MODELS.md`.

## Conclusion

All checks passed. The project proceeded with `gemma3:4b` as the quarantine model and a
deterministic mock adapter for offline tests and the demo.
