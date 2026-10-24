"""Corpus self-validation: canary uniqueness, base preservation, reproducibility."""

from __future__ import annotations

from collections import Counter

from airlock.segment import split_sentences

from eval.corpus.attack_gen import generate_attacks
from eval.corpus.benign_gen import generate_benign
from eval.corpus.generate import generate

_PLAIN = {"plain_start", "plain_middle", "plain_end"}


def test_canaries_are_unique_per_instance():
    attacks = generate_attacks(per_cell=8)
    emails = [a["canaries"]["email"] for a in attacks]
    phrases = [a["canaries"]["phrase"] for a in attacks]
    assert len(emails) == len(set(emails))
    assert len(phrases) == len(set(phrases))


def test_every_goal_sender_cell_has_at_least_eight():
    attacks = generate_attacks(per_cell=8)
    cells = Counter(f"{a['goal']}|{a['sender_variant']}" for a in attacks)
    assert cells
    assert min(cells.values()) >= 8


def test_base_sentences_preserved_for_plain_encodings():
    for attack in generate_attacks(per_cell=3):
        if attack["encoding"] not in _PLAIN:
            continue
        base_body = attack["twin"]["raw"].split("\n", 1)[1]
        for sentence in split_sentences(base_body):
            assert sentence in attack["raw"], f"lost base sentence: {sentence!r}"


def test_payload_present_for_plain_encodings():
    for attack in generate_attacks(per_cell=3):
        if attack["encoding"] in _PLAIN:
            assert attack["payload"] in attack["raw"]


def test_sender_variant_known_contact_uses_alice():
    attacks = generate_attacks(per_cell=2)
    for attack in attacks:
        if attack["sender_variant"] == "compromised_known":
            assert "alice@example.com" in attack["sender"]
            assert attack["headers"]["Authentication-Results"][0].endswith("dmarc=pass")


def test_generation_is_reproducible(tmp_path):
    generate(variants=3, per_cell=2, seed=7, out_dir=tmp_path / "a")
    generate(variants=3, per_cell=2, seed=7, out_dir=tmp_path / "b")
    assert (tmp_path / "a" / "benign.jsonl").read_bytes() == (tmp_path / "b" / "benign.jsonl").read_bytes()
    assert (tmp_path / "a" / "attacks.jsonl").read_bytes() == (tmp_path / "b" / "attacks.jsonl").read_bytes()


def test_benign_labels_have_required_keys():
    for item in generate_benign(variants=1):
        labels = item["labels"]
        for key in ("category", "request_type", "urgency", "asks_user_to_act", "deadline_sentence", "amount_sentence", "acceptable_evidence"):
            assert key in labels
