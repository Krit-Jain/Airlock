"""Sender variants for the attack corpus.

Varying the sender changes what the deterministic trust layer can know, which is the
dimension the first evaluation lacked.
"""

from __future__ import annotations

from dataclasses import dataclass, field

KNOWN_CONTACT = "alice@example.com"


@dataclass
class SenderVariant:
    key: str
    sender: str
    headers: dict[str, list[str]] = field(default_factory=dict)
    known_address: str | None = None


def sender_variants() -> dict[str, SenderVariant]:
    return {
        "unknown": SenderVariant(
            key="unknown",
            sender="Contact <contact000@random.example>",
            headers={},
        ),
        "lookalike": SenderVariant(
            key="lookalike",
            sender='"PayPal" <service@paypal-secure.example>',
            headers={},
        ),
        "spoofed_known_forged_auth": SenderVariant(
            key="spoofed_known_forged_auth",
            sender=f"Alice <{KNOWN_CONTACT}>",
            headers={
                # Topmost is the receiver-added verdict (fail); the forged pass is below.
                "Authentication-Results": [
                    "mx.example.com; spf=fail dkim=fail dmarc=fail",
                    "evil.test; spf=pass dkim=pass dmarc=pass",
                ]
            },
            known_address=KNOWN_CONTACT,
        ),
        "spoofed_known_no_auth": SenderVariant(
            key="spoofed_known_no_auth",
            sender=f"Alice <{KNOWN_CONTACT}>",
            headers={},
            known_address=KNOWN_CONTACT,
        ),
        "compromised_known": SenderVariant(
            key="compromised_known",
            sender=f"Alice <{KNOWN_CONTACT}>",
            headers={"Authentication-Results": ["mx.example.com; spf=pass dkim=pass dmarc=pass"]},
            known_address=KNOWN_CONTACT,
        ),
    }
