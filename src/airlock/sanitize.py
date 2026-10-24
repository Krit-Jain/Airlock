"""Deterministic text sanitization.

Sanitization strips hidden and invisible content before any model sees a message, and
records whether *dangerous* invisible content was present so it can be used as a trust
signal. Legitimate joiners (ZWJ, ZWNJ, variation selectors) used by Indic, Persian, and
emoji are stripped for the model but never flagged on their own.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from bs4 import BeautifulSoup

# Everything removed from model input. Includes legitimate joiners, which are stripped so
# the model sees normalized text, but which do not raise the danger flag.
_INVISIBLE_RE = re.compile(
    "["
    "\u200b-\u200f"  # zero-width space .. right-to-left mark
    "\u202a-\u202e"  # bidi embedding/override
    "\u2060-\u2064"  # word joiner .. invisible plus
    "\u2066-\u2069"  # bidi isolates
    "\ufeff"  # zero-width no-break space / BOM
    "\ufe00-\ufe0f"  # variation selectors
    "\U000e0000-\U000e007f"  # tags block
    "\u00ad"  # soft hyphen
    "]"
)

# The dangerous subset that raises the signal: tag-block characters, bidi overrides and
# isolates, and zero-width space / word joiner. Deliberately excludes ZWJ (U+200D),
# ZWNJ (U+200C), and variation selectors (U+FE00-U+FE0F).
_DANGEROUS_RE = re.compile("[\u200b\u2060\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")

_HIDDEN_CSS_CHECKS = (
    re.compile(r"display\s*:\s*none"),
    re.compile(r"visibility\s*:\s*hidden"),
    re.compile(r"font-size\s*:\s*(?:0(?![\d.])|(?<![\d.])[0-2](?:\.\d+)?px)"),
    re.compile(r"(?:max-)?(?:width|height)\s*:\s*0(?![\d.])"),
    re.compile(r"opacity\s*:\s*0(?![\d.])"),
    re.compile(r"text-indent\s*:\s*-\d+px"),
    re.compile(r"clip\s*:\s*rect\(\s*0"),
)

_WHITE = r"(?:#fff(?:fff)?|white)"
_COLOR_ON_WHITE = re.compile(rf"\bcolor\s*:\s*{_WHITE}")
_BG_WHITE = re.compile(rf"background(?:-color)?\s*:\s*{_WHITE}")

_WS_RE = re.compile(r"[ \t\f\v]+")
_NL_RE = re.compile(r"\n{2,}")


@dataclass
class SanitizeResult:
    text: str
    hidden_text_detected: bool = False
    invisible_unicode_detected: bool = False


def strip_invisible(text: str) -> str:
    """Remove all invisible/format characters from text destined for the model."""
    return _INVISIBLE_RE.sub("", text)


def _has_dangerous_invisible(text: str) -> bool:
    return _DANGEROUS_RE.search(text) is not None


def _looks_like_html(text: str) -> bool:
    return "<" in text and ">" in text and re.search(r"<[a-z!/][^>]*>", text, re.IGNORECASE) is not None


def _is_hidden_style(style: str) -> bool:
    if not style:
        return False
    lowered = style.lower()
    if any(check.search(lowered) for check in _HIDDEN_CSS_CHECKS):
        return True
    if re.search(r"position\s*:\s*absolute", lowered) and re.search(
        r"(?:left|top|right|bottom)\s*:\s*-\d", lowered
    ):
        return True
    if _COLOR_ON_WHITE.search(lowered) and _BG_WHITE.search(lowered):
        return True
    return False


def _html_to_text_and_detect(html: str) -> tuple[str, bool]:
    soup = BeautifulSoup(html, "html.parser")
    hidden = False

    for tag in soup.find_all(True):
        style = tag.get("style") or ""
        hidden_attr = tag.get("hidden") is not None or tag.get("aria-hidden") == "true"
        if hidden_attr or _is_hidden_style(style):
            if tag.get_text(strip=True):
                hidden = True
            tag.decompose()

    for tag in soup.find_all(["script", "style", "noscript", "template"]):
        tag.decompose()

    return soup.get_text("\n"), hidden


def sanitize(raw: str) -> SanitizeResult:
    """Normalize and strip hidden/invisible content, recording what was removed."""
    dangerous = _has_dangerous_invisible(raw)

    if _looks_like_html(raw):
        text, hidden = _html_to_text_and_detect(raw)
    else:
        text, hidden = raw, False

    text = strip_invisible(text)
    text = unicodedata.normalize("NFKC", text)
    text = _WS_RE.sub(" ", text)
    text = _NL_RE.sub("\n", text)
    text = text.strip()

    return SanitizeResult(
        text=text,
        hidden_text_detected=hidden,
        invisible_unicode_detected=dangerous,
    )
