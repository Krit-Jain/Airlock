"""Deterministic text sanitization.

Sanitization removes hidden and invisible content before any model sees a message, and
records whether such content was present so it can be used as a trust signal. The model
is never asked to detect hidden text; code does it.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from bs4 import BeautifulSoup

# Zero-width, bidi-control, tag, and other format characters that can be used to hide
# instructions or confuse a model. Stripping is also the detection mechanism.
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

_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|"
    r"visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0|"
    r"width\s*:\s*0|"
    r"height\s*:\s*0|"
    r"opacity\s*:\s*0|"
    r"position\s*:\s*absolute\s*;\s*(left|top|right)\s*:\s*-",
    re.IGNORECASE,
)

_WS_RE = re.compile(r"[ \t\f\v]+")
_NL_RE = re.compile(r"\n{2,}")


@dataclass
class SanitizeResult:
    text: str
    hidden_text_detected: bool = False
    invisible_unicode_detected: bool = False


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi-control, tag, and other invisible characters."""
    return _INVISIBLE_RE.sub("", text)


def _looks_like_html(text: str) -> bool:
    return "<" in text and ">" in text and re.search(r"<[a-z!/][^>]*>", text, re.IGNORECASE) is not None


def _html_to_text_and_detect(html: str) -> tuple[str, bool]:
    soup = BeautifulSoup(html, "html.parser")
    hidden = False

    for tag in soup.find_all(True):
        style = tag.get("style") or ""
        hidden_attr = tag.get("hidden") is not None or tag.get("aria-hidden") == "true"
        if hidden_attr or _HIDDEN_STYLE_RE.search(style):
            if tag.get_text(strip=True):
                hidden = True
            tag.decompose()

    for tag in soup.find_all(["script", "style", "noscript", "template"]):
        tag.decompose()

    return soup.get_text("\n"), hidden


def sanitize(raw: str) -> SanitizeResult:
    """Normalize and strip hidden/invisible content, recording what was removed."""
    invisible = strip_invisible(raw) != raw

    if _looks_like_html(raw):
        text, hidden = _html_to_text_and_detect(raw)
    else:
        text, hidden = raw, False

    text = unicodedata.normalize("NFKC", text)
    text = _WS_RE.sub(" ", text)
    text = _NL_RE.sub("\n", text)
    text = text.strip()

    return SanitizeResult(
        text=text,
        hidden_text_detected=hidden,
        invisible_unicode_detected=invisible,
    )
