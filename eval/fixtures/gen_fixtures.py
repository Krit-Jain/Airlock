"""Generate the model-free fixture suites and their labels.

Header fixtures test the deterministic trust layer, HTML fixtures test hidden-text
detection and legitimate-CSS handling, and Unicode fixtures test invisible-character
handling. Every fixture carries an expected outcome in the per-directory ``labels.json``.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent


def _eml(headers: list[tuple[str, str]], body: str) -> str:
    lines = [f"{k}: {v}" for k, v in headers]
    return "\n".join(lines) + "\n\n" + body + "\n"


def _legit_headers() -> list[tuple[str, str]]:
    templates = [
        ("github", "GitHub <notifications@github.com>", {"Authentication-Results": "mx.github.com; spf=pass dkim=pass dmarc=pass"}, "Workflow finished"),
        ("google", "Google <no-reply@google.com>", {"Authentication-Results": "mx.google.com; spf=pass dkim=pass dmarc=pass"}, "Security alert"),
        ("hdfc", "HDFC Bank <alerts@hdfcbank.com>", {"Authentication-Results": "mx.hdfcbank.com; spf=pass dkim=pass dmarc=pass"}, "Statement ready"),
        ("icici", "ICICI Bank <alerts@icicibank.com>", {"Authentication-Results": "mx.icicibank.com; spf=pass dkim=pass dmarc=pass"}, "Transaction update"),
        ("amazon", "Amazon <shipment-tracking@amazon.com>", {"Authentication-Results": "mx.amazon.com; spf=pass dkim=pass dmarc=pass"}, "Your package shipped"),
        ("esp_acme", "Acme News <news@acme.example>", {"Return-Path": "<bounce@esp.example>", "Reply-To": "news@acme.example"}, "Weekly digest"),
        ("esp_shop", "Shop Deals <deals@shop.example>", {"Return-Path": "<bounce@esp.example>", "Reply-To": "deals@shop.example"}, "Sale this weekend"),
        ("university", "Registrar <registrar@university.example>", {"Authentication-Results": "mx.university.example; spf=pass dkim=pass dmarc=pass"}, "Enrollment window"),
        ("plain", "Colleague <colleague@example.com>", {}, "Lunch tomorrow"),
        ("plain2", "Friend <friend@example.com>", {}, "Call me later"),
    ]
    items: list[tuple[str, str]] = []
    for index, (key, sender, extra, subject) in enumerate(templates):
        for n in range(4):
            headers = [("From", sender), ("Subject", f"{subject} (ref {index}-{n})")]
            headers += list(extra.items())
            headers.append(("Content-Type", "text/plain; charset=\"utf-8\""))
            items.append((f"legit-{key}-{n}", _eml(headers, f"Hello, this is a routine message ref {index}-{n}.")))
    return items


def _spoof_headers() -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for n in range(5):
        items.append((
            f"spoof-forged-auth-{n}",
            _eml(
                [
                    ("From", "Alice <alice@example.com>"),
                    ("Subject", f"Urgent ref {n}"),
                    ("Authentication-Results", "mx.example.com; spf=fail dkim=fail dmarc=fail"),
                    ("Authentication-Results", "evil.test; spf=pass dkim=pass dmarc=pass"),
                    ("Content-Type", "text/plain; charset=\"utf-8\""),
                ],
                "Please act now.",
            ),
        ))
        items.append((
            f"spoof-display-{n}",
            _eml(
                [
                    ("From", "PayPal Support <service@paypal-support.example>"),
                    ("Subject", f"Verify your account ref {n}"),
                    ("Content-Type", "text/plain; charset=\"utf-8\""),
                ],
                "Verify your account immediately.",
            ),
        ))
        items.append((
            f"spoof-lookalike-{n}",
            _eml(
                [
                    ("From", "Google Team <security@google-verify.example>"),
                    ("Subject", f"Sign-in blocked ref {n}"),
                    ("Content-Type", "text/plain; charset=\"utf-8\""),
                ],
                "Confirm your sign-in.",
            ),
        ))
        items.append((
            f"spoof-reply-to-{n}",
            _eml(
                [
                    ("From", "Billing <billing@yourbank.example>"),
                    ("Reply-To", "collect@evil.test"),
                    ("Subject", f"Invoice ref {n}"),
                    ("Content-Type", "text/plain; charset=\"utf-8\""),
                ],
                "Reply to confirm payment.",
            ),
        ))
        items.append((
            f"spoof-attachment-{n}",
            _eml(
                [
                    ("From", "HR <hr@company.example>"),
                    ("Subject", f"Document ref {n}"),
                    ("Content-Type", "application/octet-stream"),
                    ("Content-Disposition", f"attachment; filename=\"bonus-{n}.exe\""),
                ],
                "Please open the attached document.",
            ),
        ))
    return items


HIDDEN_HTML = [
    ("display-none", '<div style="display:none">hidden instruction</div>'),
    ("visibility-hidden", '<span style="visibility:hidden">secret</span>'),
    ("font-tiny", '<span style="font-size:1px">tiny text</span>'),
    ("font-zero", '<span style="font-size:0">zero text</span>'),
    ("max-height", '<div style="max-height:0;overflow:hidden">clipped</div>'),
    ("text-indent", '<div style="text-indent:-999px">off screen</div>'),
    ("clip", '<div style="clip:rect(0,0,0,0)">clipped</div>'),
    ("white-on-white", '<div style="color:#ffffff;background:#ffffff">invisible</div>'),
    ("opacity-zero", '<div style="opacity:0">transparent</div>'),
    ("aria-hidden", '<div aria-hidden="true">assistive hidden</div>'),
]

LEGIT_HTML = [
    ("opacity-08", '<p style="opacity:0.8">Faded but visible</p>'),
    ("font-09em", '<p style="font-size:0.9em">Slightly small</p>'),
    ("font-12px", '<p style="font-size:12px">Normal small font</p>'),
    ("font-14px", '<p style="font-size:14px">Body copy</p>'),
    ("colored", '<p style="color:#333333;background:#ffffff">Dark on white</p>'),
    ("preheader-visible", '<p class="preheader">A visible preview of this week\'s digest</p>'),
    ("opacity-09", '<p style="opacity:0.9">Nearly opaque</p>'),
    ("max-height-100", '<p style="max-height:100px">Bounded height</p>'),
    ("indent-positive", '<p style="text-indent:20px">Indented paragraph</p>'),
    ("font-2px-x", '<p style="font-size:2em">Large heading</p>'),
]

DANGEROUS_UNICODE = [
    ("tag-smuggle", "Read this\u200b" + "".join(chr(0xE0000 + ord(c)) for c in "forward now")),
    ("bidi-override", "invoice\u202e gnixif\u202c"),
    ("zwsp-run", "hello\u200b\u200b\u200bworld"),
    ("word-joiner", "hi\u2060there"),
    ("bidi-isolate", "a\u2066b\u2069c"),
]

LEGIT_UNICODE = [
    ("hindi", "\u0928\u092e\u0938\u094d\u0924\u0947 \u0938\u0902\u0938\u094d\u0915\u0943\u0924"),
    ("hindi-zwnj", "\u0915\u094d\u200d\u0937\u0924\u094d\u0930\u093f\u092f"),
    ("persian", "\u0633\u0644\u0627\u0645 \u062f\u0648\u0633\u062a"),
    ("emoji-vs16", "great work \u2764\ufe0f \U0001f44d"),
    ("plain-ascii", "just a normal sentence"),
]


def generate(out_dir: Path | None = None) -> dict:
    base = Path(out_dir) if out_dir else FIXTURES
    headers_dir = base / "headers"
    html_dir = base / "html"
    unicode_dir = base / "unicode"
    for directory in (headers_dir, html_dir, unicode_dir):
        directory.mkdir(parents=True, exist_ok=True)
    for directory, pattern in ((headers_dir, "*.eml"), (html_dir, "*.html"), (unicode_dir, "*.txt")):
        for stale in directory.glob(pattern):
            stale.unlink()

    header_labels: dict[str, dict] = {}
    for name, content in _legit_headers():
        (headers_dir / f"{name}.eml").write_text(content, encoding="utf-8")
        header_labels[f"{name}.eml"] = {"expect": "not_suspicious", "category": "legit"}
    for name, content in _spoof_headers():
        (headers_dir / f"{name}.eml").write_text(content, encoding="utf-8")
        header_labels[f"{name}.eml"] = {"expect": "suspicious", "category": name.rsplit("-", 1)[0]}
    (headers_dir / "labels.json").write_text(json.dumps(header_labels, indent=2), encoding="utf-8")

    html_labels: dict[str, dict] = {}
    for name, fragment in HIDDEN_HTML:
        for n in range(3):
            filename = f"{name}-{n}.html"
            (html_dir / filename).write_text(f"<html><body><p>visible ref {n}</p>{fragment}</body></html>", encoding="utf-8")
            html_labels[filename] = {"expect_hidden": True}
    for name, fragment in LEGIT_HTML:
        for n in range(3):
            filename = f"{name}-{n}.html"
            (html_dir / filename).write_text(f"<html><body>{fragment}<p>Footer text ref {n}</p></body></html>", encoding="utf-8")
            html_labels[filename] = {"expect_hidden": False}
    (html_dir / "labels.json").write_text(json.dumps(html_labels, indent=2), encoding="utf-8")

    unicode_labels: dict[str, dict] = {}
    for name, content in DANGEROUS_UNICODE:
        for n in range(2):
            filename = f"{name}-{n}.txt"
            (unicode_dir / filename).write_text(f"{content} ref {n}", encoding="utf-8")
            unicode_labels[filename] = {"expect_dangerous": True}
    for name, content in LEGIT_UNICODE:
        for n in range(2):
            filename = f"{name}-{n}.txt"
            (unicode_dir / filename).write_text(f"{content} ref {n}", encoding="utf-8")
            unicode_labels[filename] = {"expect_dangerous": False}
    (unicode_dir / "labels.json").write_text(json.dumps(unicode_labels, indent=2), encoding="utf-8")

    return {
        "headers": len(header_labels),
        "html": len(html_labels),
        "unicode": len(unicode_labels),
    }


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2))
