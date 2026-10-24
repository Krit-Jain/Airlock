"""Deterministic trust signals.

Trust labels are computed only by this module. The quarantined model's opinion of a
message can never raise its trust; trust is a code-only input to ranking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .models import Message, TrustLabel, TrustReason
from .sanitize import SanitizeResult

_EMAIL_RE = re.compile(r"<([^>]+@[^>]+)>")
_BARE_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_RISKY_EXT = re.compile(r"\.(exe|scr|bat|cmd|ps1|js|vbs|jar|lnk|msi|hta|com)$", re.IGNORECASE)
_LINK_TAG = re.compile(r"<a\b[^>]*href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)

# Brand -> expected sending domain. A display name that claims a brand but is sent from
# another domain is treated as a spoof.
_BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "github": "github.com",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "axis": "axisbank.com",
    "sbi": "sbi.co.in",
}


@dataclass
class SignalConfig:
    """User-provided context for contact and authentication checks."""

    known_contacts: set[str] = field(default_factory=set)
    sent_senders: set[str] = field(default_factory=set)

    @classmethod
    def empty(cls) -> "SignalConfig":
        return cls()


def _first(headers: dict, key: str) -> str:
    """Return a header value as a string, tolerating single values or lists."""
    value = headers.get(key)
    if value is None:
        return ""
    if isinstance(value, list):
        return value[0] if value else ""
    return str(value)


def _domain(addr: str) -> str:
    return urlparse("//" + addr.split("@")[-1].strip()).hostname or addr.split("@")[-1].strip().lower()


def _display_and_address(header_value: str) -> tuple[str, str]:
    header_value = (header_value or "").strip()
    match = _EMAIL_RE.search(header_value)
    if match:
        addr = match.group(1).strip()
        display = header_value[: match.start()].strip().strip('"')
        return display, addr
    bare = _BARE_EMAIL_RE.search(header_value)
    if bare:
        return "", bare.group(0)
    return header_value, ""


def _auth_results(headers: dict) -> tuple[bool, bool]:
    """Return (has_auth_results, all_pass) using the topmost Authentication-Results."""
    header = _first(headers, "authentication-results")
    if not header:
        return False, False
    lower = header.lower()
    checks = {
        "spf": "spf=pass" in lower,
        "dkim": "dkim=pass" in lower,
        "dmarc": "dmarc=pass" in lower,
    }
    return True, all(checks.values())


def _analyze_links(raw_text: str) -> tuple[bool, bool]:
    """Return (link_mismatch, many_links)."""
    mismatched = False
    count = 0
    for href, text in _LINK_TAG.findall(raw_text):
        count += 1
        href_domain = _domain(href)
        text_stripped = BeautifulSoup(text, "html.parser").get_text().strip()
        text_domain = _domain(text_stripped) if "@" in text_stripped or "." in text_stripped else ""
        if text_domain and href_domain and text_domain != href_domain:
            mismatched = True
    return mismatched, count >= 8


def _risky_attachment(message: Message) -> bool:
    """Flag risky extensions based on actual attachment filenames, not message body."""
    return any(_RISKY_EXT.search(name) for name in message.attachments)


def _display_name_spoof(display: str, from_addr: str) -> bool:
    if not display:
        return False
    if "@" in display:
        return True
    from_domain = _domain(from_addr)
    lowered = display.lower()
    for brand, expected in _BRAND_DOMAINS.items():
        if re.search(rf"\b{re.escape(brand)}\b", lowered):
            if not (from_domain == expected or from_domain.endswith("." + expected)):
                return True
    return False


def _email_signals(message: Message, sanitized: SanitizeResult, config: SignalConfig) -> tuple[TrustLabel, list[TrustReason]]:
    reasons: list[TrustReason] = []
    headers = {k.lower(): v for k, v in message.headers.items()}

    from_display, from_addr = _display_and_address(message.sender)
    _, reply_to_addr = _display_and_address(_first(headers, "reply-to"))
    _, return_path_addr = _display_and_address(_first(headers, "return-path"))

    from_domain = _domain(from_addr)
    has_auth, auth_pass = _auth_results(headers)

    if has_auth and not auth_pass:
        reasons.append(TrustReason.AUTH_FAIL)
    elif has_auth and auth_pass:
        reasons.append(TrustReason.AUTH_PASS)

    reply_to_mismatch = bool(reply_to_addr) and from_domain != _domain(reply_to_addr)
    return_path_mismatch = bool(return_path_addr) and from_domain != _domain(return_path_addr)
    if reply_to_mismatch or return_path_mismatch:
        reasons.append(TrustReason.DOMAIN_MISMATCH)

    if _display_name_spoof(from_display, from_addr):
        reasons.append(TrustReason.DISPLAY_NAME_SPOOF)

    if sanitized.hidden_text_detected:
        reasons.append(TrustReason.HIDDEN_TEXT)
    if sanitized.invisible_unicode_detected:
        reasons.append(TrustReason.INVISIBLE_UNICODE)

    if message.part_mismatch:
        reasons.append(TrustReason.PART_MISMATCH)

    link_mismatch, many_links = _analyze_links(message.raw_text)
    if link_mismatch:
        reasons.append(TrustReason.LINK_MISMATCH)
    if many_links:
        reasons.append(TrustReason.MANY_LINKS)

    if _risky_attachment(message):
        reasons.append(TrustReason.RISKY_ATTACHMENT)

    normalized_from = from_addr.lower()
    known = normalized_from in config.known_contacts or normalized_from in config.sent_senders
    if known:
        reasons.append(TrustReason.KNOWN_CONTACT)
    else:
        reasons.append(TrustReason.FIRST_TIME_SENDER)

    strong_suspicion = reply_to_mismatch or any(
        r in reasons
        for r in (
            TrustReason.HIDDEN_TEXT,
            TrustReason.INVISIBLE_UNICODE,
            TrustReason.LINK_MISMATCH,
            TrustReason.RISKY_ATTACHMENT,
            TrustReason.DISPLAY_NAME_SPOOF,
            TrustReason.PART_MISMATCH,
            TrustReason.AUTH_FAIL,
        )
    )
    if strong_suspicion:
        return TrustLabel.SUSPICIOUS, reasons

    if known:
        return (TrustLabel.VERIFIED_KNOWN if auth_pass else TrustLabel.KNOWN_UNVERIFIED), reasons

    return TrustLabel.UNKNOWN, reasons


def _whatsapp_signals(message: Message, config: SignalConfig) -> tuple[TrustLabel, list[TrustReason]]:
    reasons = [TrustReason.UNVERIFIED_CHAT]
    sender = message.sender.strip().lower()
    known = sender in config.known_contacts
    reasons.append(TrustReason.KNOWN_CONTACT if known else TrustReason.FIRST_TIME_SENDER)
    label = TrustLabel.KNOWN_UNVERIFIED if known else TrustLabel.UNKNOWN
    return label, reasons


def compute_signals(
    message: Message,
    sanitized: SanitizeResult,
    config: SignalConfig | None = None,
) -> tuple[TrustLabel, list[TrustReason]]:
    config = config or SignalConfig.empty()
    if message.source == "whatsapp":
        return _whatsapp_signals(message, config)
    return _email_signals(message, sanitized, config)
