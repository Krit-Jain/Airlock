# Submission checklist

Hacktoberfest Open-Source AI Challenge, Week 3: Slow and Steady.

- Contest page: https://dev.to/challenges/hacktoberfest-week3-2026-10-19
- Window: October 19 to October 25, 2026, 11:59 PM PDT.
- Judging: Writing Quality (weighted most), Relevance to the prompt and theme, Creativity,
  Technical Execution, Use of Partner Technology (optional).

## Hard requirements

- [x] New project built inside the contest window.
- [x] Public GitHub repository: https://github.com/Krit-Jain/Airlock
- [x] Open-source license (MIT) in `LICENSE`.
- [x] Open-source AI at the core: `gemma3:4b` run locally through Ollama.
- [x] Local inference, no cloud model, no network in the core pipeline.
- [x] README with setup and usage.
- [x] Test suite passing (`uv run pytest`, 83 tests).
- [x] Evaluation with measured results (`results/REPORT.md`).
- [x] README numbers match `results/REPORT.md`.
- [x] Honest limitations stated (`docs/THREAT_MODEL.md` and the post).
- [ ] DEV post published (draft ready at `docs/DEV_POST.md`).

## Publishing the DEV post

1. Open `docs/DEV_POST.md` and paste it into a new DEV post.
2. Keep the front matter tags: `devchallenge` and `hf26challenge`.
3. Confirm the canonical repo link is present in the Code section.
4. Add a demo video or a screenshot of the brief if available (optional but recommended).
5. Publish before the deadline: October 25, 2026, 11:59 PM PDT (about October 26,
   12:29 PM IST).

## Optional

- [x] Demo video at `docs/demo.mp4` (2:44, narrated); upload it to DEV when publishing.
- [ ] Agent session embed via DevRelay (optional; requires the MLH connection).
- [ ] Sentry traces: `src/airlock/tracing.py` implements span helpers, but no Sentry run
      with a DSN was captured, so the Sentry track is not claimed.

## Prize categories

- Best Use of Gemma (featured): `gemma3:4b` is the quarantine extractor, run locally with
  schema-constrained decoding. This is the only partner track claimed.

## Reproducing the results

```bash
uv sync
uv run pytest                 # 83 tests
uv run airlock eval           # calibration, fixtures, schema, cross-message, agent, steering
```

Every expensive call is cached under `results/cache/`, so a run resumes after interruption.
The full test split takes a few hours on a 4 GB-VRAM laptop; the deterministic stages take
minutes.
