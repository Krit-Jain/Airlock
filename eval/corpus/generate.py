"""Generate the paired corpus and write it to disk.

Writes ``benign.jsonl``, ``attacks.jsonl``, ``MANIFEST.json``, and ``CHECKSUMS.txt``. The
dev/test split is deterministic from the seed so it can be frozen.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from pathlib import Path

from .attack_gen import generate_attacks
from .benign_gen import generate_benign

CORPUS_DIR = Path(__file__).parent


def _assign_split(items: list[dict], rng: random.Random, dev_fraction: float) -> None:
    for item in items:
        item["split"] = "dev" if rng.random() < dev_fraction else "test"


def _write_jsonl(path: Path, items: list[dict]) -> None:
    lines = [json.dumps(item, sort_keys=True) for item in items]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(variants: int = 6, per_cell: int = 8, dev_fraction: float = 0.3, seed: int = 0, out_dir: Path | None = None) -> dict:
    out = Path(out_dir) if out_dir else CORPUS_DIR
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    benign = generate_benign(variants=variants)
    attacks = generate_attacks(per_cell=per_cell)
    _assign_split(benign, rng, dev_fraction)
    _assign_split(attacks, rng, dev_fraction)

    _write_jsonl(out / "benign.jsonl", benign)
    _write_jsonl(out / "attacks.jsonl", attacks)

    cells = Counter(f"{a['goal']}|{a['sender_variant']}" for a in attacks)
    manifest = {
        "seed": seed,
        "dev_fraction": dev_fraction,
        "benign_total": len(benign),
        "attacks_total": len(attacks),
        "benign_split": dict(Counter(b["split"] for b in benign)),
        "attacks_split": dict(Counter(a["split"] for a in attacks)),
        "cells": dict(sorted(cells.items())),
        "min_cell": min(cells.values()) if cells else 0,
        "goals": sorted({a["goal"] for a in attacks}),
        "sender_variants": sorted({a["sender_variant"] for a in attacks}),
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    checksums = ["# sha256"]
    for name in ("benign.jsonl", "attacks.jsonl", "MANIFEST.json"):
        checksums.append(f"{_sha256(out / name)}  {name}")
    (out / "CHECKSUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")

    return manifest


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2))
