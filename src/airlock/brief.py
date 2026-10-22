"""Human-only HTML brief rendering.

The brief is generated statically with Jinja2 autoescape on, contains no external
assets, and defangs every link so it is shown as text rather than clickable.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import BriefItem, ResolvedAmount, TrustLabel, TrustReason
from .schema import Category, RequestType, Urgency

_URL = re.compile(r"https?://[^\s<>\"')\]]+")


def _defang(text: str) -> str:
    def replace(match: re.Match) -> str:
        url = match.group(0)
        domain = urlparse(url).netloc or url
        return f"[link to {domain}]"

    return _URL.sub(replace, text)


def _to_brief_item(row: dict) -> BriefItem:
    sentences = json.loads(row["sentences"])
    evidence = json.loads(row["evidence"])
    quotes = [sentences[i] for i in evidence if 0 <= i < len(sentences)]
    amount = None
    if row["amount_value"] is not None:
        amount = ResolvedAmount(value=row["amount_value"], currency=row["amount_currency"])
    return BriefItem(
        message_id=row["id"],
        sender=row["sender"],
        trust=TrustLabel(row["trust"]),
        trust_reasons=[TrustReason(r) for r in json.loads(row["trust_reasons"])],
        category=Category(row["category"]) if row["category"] else None,
        request_type=RequestType(row["request_type"]) if row["request_type"] else None,
        urgency=Urgency(row["urgency"]) if row["urgency"] else None,
        asks_user_to_act=bool(row["asks_user_to_act"]) if row["asks_user_to_act"] is not None else None,
        quotes=quotes,
        deadline=datetime.fromisoformat(row["deadline"]) if row["deadline"] else None,
        amount=amount,
        ts=datetime.fromisoformat(row["ts"]) if row["ts"] else None,
        section=row["section"],
    )


def _items(store) -> list[BriefItem]:
    rows = store.all_brief_rows()
    items = [_to_brief_item(row) for row in rows]
    section_order = {"needs_you": 0, "deadlines_amounts": 1, "review": 2, "fyi": 3}
    items.sort(key=lambda item: (section_order.get(item.section, 9), item.urgency.value if item.urgency else "none"))
    return items


def render_brief(store, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html", "j2"]),
    )
    env.filters["defang"] = _defang
    template = env.get_template("brief.html.j2")
    html = template.render(items=_items(store))
    output_path.write_text(html, encoding="utf-8")
    return output_path
