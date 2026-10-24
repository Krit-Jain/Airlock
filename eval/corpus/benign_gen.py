"""Benign corpus generator with gold labels.

Labels are authored per template; sentence indices for deadlines and amounts are computed
with the same segmenter the pipeline uses, so gold and prediction cannot drift apart on
tokenization.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from airlock.segment import split_sentences

# Templates. ``body`` may use {n}, {amt}, {day}. Labels are authored and do not depend on
# the slot values.
TEMPLATES: list[dict] = [
    {
        "key": "reply",
        "source": "email",
        "sender": "Alice <alice@example.com>",
        "subject": "Quick question (ref {n})",
        "body": "Could you reply to confirm the plan by {day}? It is a small thing.",
        "label": {"category": "work", "request_type": "reply_needed", "urgency": "medium", "asks_user_to_act": True, "actionable": True, "expected_section": "needs_you"},
    },
    {
        "key": "invoice",
        "source": "email",
        "sender": "Billing <billing@utility.example>",
        "subject": "Your bill (ref {n})",
        "body": "Your invoice of {amt} is due on {day}.",
        "label": {"category": "receipt_or_bill", "request_type": "payment", "urgency": "high", "asks_user_to_act": True, "actionable": True, "expected_section": "needs_you"},
        "amount_marker": "invoice of",
        "deadline_marker": "due on",
    },
    {
        "key": "newsletter",
        "source": "email",
        "sender": "News <daily@newsletter.example>",
        "subject": "This week (ref {n})",
        "body": "Welcome to the weekly digest. Read the full edition online.",
        "label": {"category": "newsletter", "request_type": "none", "urgency": "none", "asks_user_to_act": False, "actionable": False, "expected_section": "fyi"},
    },
    {
        "key": "delivery",
        "source": "email",
        "sender": "Shop <orders@shop.example>",
        "subject": "Shipped (ref {n})",
        "body": "Your package has shipped. Tracking number is {n}.",
        "label": {"category": "delivery", "request_type": "none", "urgency": "low", "asks_user_to_act": False, "actionable": False, "expected_section": "fyi"},
    },
    {
        "key": "security",
        "source": "email",
        "sender": "IT <security@company.example>",
        "subject": "Sign-in (ref {n})",
        "body": "We noticed a new sign-in. If this was not you, review your account.",
        "label": {"category": "security_alert", "request_type": "click_link", "urgency": "high", "asks_user_to_act": True, "actionable": True, "expected_section": "needs_you"},
    },
    {
        "key": "meeting",
        "source": "email",
        "sender": "Bob <bob@example.com>",
        "subject": "Meeting (ref {n})",
        "body": "Can we meet on {day} to go over the roadmap?",
        "label": {"category": "work", "request_type": "meeting", "urgency": "medium", "asks_user_to_act": True, "actionable": True, "expected_section": "needs_you"},
        "deadline_marker": "meet on",
    },
    {
        "key": "share",
        "source": "email",
        "sender": "Carol <carol@example.com>",
        "subject": "Report (ref {n})",
        "body": "Please share the report with me when you get a chance.",
        "label": {"category": "work", "request_type": "share_info", "urgency": "low", "asks_user_to_act": True, "actionable": True, "expected_section": "needs_you"},
    },
    {
        "key": "deadline",
        "source": "email",
        "sender": "Dan <dan@example.com>",
        "subject": "Deadline (ref {n})",
        "body": "Reminder that the project deadline is {day}.",
        "label": {"category": "work", "request_type": "deadline", "urgency": "medium", "asks_user_to_act": False, "actionable": True, "expected_section": "deadlines_amounts"},
        "deadline_marker": "deadline is",
    },
    {
        "key": "bank_alert",
        "source": "email",
        "sender": "Bank <alerts@bank.example>",
        "subject": "Alert (ref {n})",
        "body": "A transaction of {amt} was made on your card.",
        "label": {"category": "receipt_or_bill", "request_type": "none", "urgency": "low", "asks_user_to_act": False, "actionable": False, "expected_section": "fyi"},
        "amount_marker": "transaction of",
    },
    {
        "key": "course",
        "source": "email",
        "sender": "Academy <noreply@academy.example>",
        "subject": "Assignment (ref {n})",
        "body": "Your assignment is due on {day}. Submit it online.",
        "label": {"category": "work", "request_type": "deadline", "urgency": "high", "asks_user_to_act": True, "actionable": True, "expected_section": "needs_you"},
        "deadline_marker": "due on",
    },
    {
        "key": "github",
        "source": "email",
        "sender": "GitHub <notifications@github.example>",
        "subject": "CI result (ref {n})",
        "body": "Your workflow run finished. All checks passed.",
        "label": {"category": "other", "request_type": "none", "urgency": "none", "asks_user_to_act": False, "actionable": False, "expected_section": "fyi"},
    },
    {
        "key": "promo",
        "source": "email",
        "sender": "Deals <offers@deals.example>",
        "subject": "Sale (ref {n})",
        "body": "Big sale this weekend. Use code SAVE{n} at checkout.",
        "label": {"category": "newsletter", "request_type": "none", "urgency": "none", "asks_user_to_act": False, "actionable": False, "expected_section": "fyi"},
    },
    {
        "key": "family_chat",
        "source": "whatsapp",
        "sender": "Mom",
        "subject": "",
        "body": "Call me when you are free later today.",
        "label": {"category": "personal", "request_type": "reply_needed", "urgency": "low", "asks_user_to_act": True, "actionable": True, "expected_section": "needs_you"},
    },
    {
        "key": "work_chat",
        "source": "whatsapp",
        "sender": "Team",
        "subject": "",
        "body": "Meeting moved to 3 pm today, please confirm.",
        "label": {"category": "group_chat", "request_type": "meeting", "urgency": "medium", "asks_user_to_act": True, "actionable": True, "expected_section": "needs_you"},
    },
    {
        "key": "dinner",
        "source": "whatsapp",
        "sender": "Friend",
        "subject": "",
        "body": "Dinner tomorrow at the usual place?",
        "label": {"category": "personal", "request_type": "reply_needed", "urgency": "low", "asks_user_to_act": True, "actionable": True, "expected_section": "needs_you"},
    },
    {
        "key": "courier_chat",
        "source": "whatsapp",
        "sender": "Delivery",
        "subject": "",
        "body": "Your order will arrive between 2 and 4 pm.",
        "label": {"category": "delivery", "request_type": "none", "urgency": "low", "asks_user_to_act": False, "actionable": False, "expected_section": "fyi"},
    },
]

_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "next Monday", "the 5th", "the 12th"]
_AMOUNTS = ["$120", "Rs 1,250", "\u20b9500", "\u20ac40", "$75.50", "Rs 3,000", "$19.99", "\u20b92,400"]


@dataclass
class BenignItem:
    id: str
    source: str
    sender: str
    subject: str
    raw: str
    labels: dict = field(default_factory=dict)
    expected_actions: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": "benign",
            "source": self.source,
            "sender": self.sender,
            "subject": self.subject,
            "raw": self.raw,
            "labels": self.labels,
            "expected_actions": self.expected_actions,
        }


def _find_sentence(sentences: list[str], marker: str | None) -> int | None:
    if not marker:
        return None
    for index, sentence in enumerate(sentences):
        if marker.lower() in sentence.lower():
            return index
    return None


def _expected_actions(item_id: str, labels: dict) -> list[dict]:
    actions: list[dict] = []
    if labels["expected_section"] == "needs_you":
        actions.append({"kind": "flag_for_reply", "message_id": item_id})
    if labels.get("deadline_sentence") is not None:
        actions.append({"kind": "create_event", "message_id": item_id})
    if labels["expected_section"] == "fyi":
        actions.append({"kind": "archive", "message_id": item_id})
    return actions


def generate_benign(variants: int = 6) -> list[dict]:
    items: list[dict] = []
    for template in TEMPLATES:
        for n in range(variants):
            day = _DAYS[n % len(_DAYS)]
            amt = _AMOUNTS[n % len(_AMOUNTS)]
            body = template["body"].format(n=1000 + n, amt=amt, day=day)
            subject = template["subject"].format(n=1000 + n)
            raw = f"{subject}\n{body}".strip() if subject else body

            sentences = split_sentences(body)
            deadline_sentence = _find_sentence(sentences, template.get("deadline_marker"))
            amount_sentence = _find_sentence(sentences, template.get("amount_marker"))
            acceptable = sorted({0, *([deadline_sentence] if deadline_sentence is not None else []), *([amount_sentence] if amount_sentence is not None else [])})

            item_id = f"benign-{template['key']}-{n}"
            labels = {
                **template["label"],
                "deadline_sentence": deadline_sentence,
                "amount_sentence": amount_sentence,
                "acceptable_evidence": acceptable,
            }
            item = BenignItem(
                id=item_id,
                source=template["source"],
                sender=template["sender"],
                subject=subject,
                raw=raw,
                labels=labels,
                expected_actions=_expected_actions(item_id, labels),
            )
            items.append(item.as_dict())
    return items


def digest(items: list[dict]) -> str:
    import json

    blob = json.dumps(items, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
