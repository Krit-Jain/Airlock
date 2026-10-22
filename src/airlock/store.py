"""Local SQLite store.

The store is the only place sanitized message text and quote text live on disk. Typed
records are exposed to MCP clients; raw and sanitized text are kept local for the brief.
Processing is resumable because every message is keyed by a content hash.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Message, ResolvedAmount, ResolvedRecord, TrustLabel, TrustReason
from .schema import Category, RequestType, Urgency


def message_id_for(source: str, sender: str, raw_text: str) -> str:
    digest = hashlib.sha256(f"{source}\x00{sender}\x00{raw_text}".encode("utf-8")).hexdigest()
    return digest[:16]


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _parse_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                sender TEXT NOT NULL,
                ts TEXT,
                raw_text TEXT NOT NULL,
                sanitized_text TEXT NOT NULL,
                sentences TEXT NOT NULL,
                headers TEXT NOT NULL,
                trust TEXT NOT NULL,
                trust_reasons TEXT NOT NULL,
                category TEXT,
                urgency TEXT,
                request_type TEXT,
                asks_user_to_act INTEGER,
                evidence TEXT NOT NULL,
                deadline_sentence INTEGER,
                amount_sentence INTEGER,
                deadline TEXT,
                amount_value REAL,
                amount_currency TEXT,
                unparsed INTEGER NOT NULL DEFAULT 0,
                disputed INTEGER NOT NULL DEFAULT 0,
                section TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def is_processed(self, message_id: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM messages WHERE id = ?", (message_id,)).fetchone()
        return row is not None

    def save_message(
        self,
        message: Message,
        extraction: Any | None,
        urgency: Urgency | None,
        deadline: datetime | None,
        amount: ResolvedAmount | None,
        section: str,
        unparsed: bool,
        disputed: bool,
    ) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO messages (
                id, source, sender, ts, raw_text, sanitized_text, sentences, headers,
                trust, trust_reasons, category, urgency, request_type, asks_user_to_act,
                evidence, deadline_sentence, amount_sentence, deadline, amount_value,
                amount_currency, unparsed, disputed, section
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message.id,
                message.source,
                message.sender,
                _iso(message.ts),
                message.raw_text,
                message.sanitized_text,
                json.dumps(message.sentences),
                json.dumps(message.headers),
                message.trust.value,
                json.dumps([r.value for r in message.trust_reasons]),
                extraction.category.value if extraction else None,
                urgency.value if urgency else None,
                extraction.request_type.value if extraction else None,
                extraction.asks_user_to_act if extraction else None,
                json.dumps(extraction.evidence if extraction else []),
                extraction.deadline_sentence if extraction else None,
                extraction.amount_sentence if extraction else None,
                _iso(deadline),
                amount.value if amount else None,
                amount.currency if amount else None,
                int(unparsed),
                int(disputed),
                section,
            ),
        )
        self._conn.commit()

    def get_record(self, message_id: str) -> ResolvedRecord | None:
        row = self._conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def list_records(
        self,
        trust: TrustLabel | None = None,
        category: Category | None = None,
        min_urgency: Urgency | None = None,
    ) -> list[ResolvedRecord]:
        query = "SELECT * FROM messages WHERE 1=1"
        params: list[Any] = []
        if trust is not None:
            query += " AND trust = ?"
            params.append(trust.value)
        if category is not None:
            query += " AND category = ?"
            params.append(category.value)
        if min_urgency is not None:
            query += " AND urgency = ?"
            params.append(min_urgency.value)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def _row_to_record(self, row: sqlite3.Row) -> ResolvedRecord:
        amount = None
        if row["amount_value"] is not None:
            amount = ResolvedAmount(value=row["amount_value"], currency=row["amount_currency"])
        return ResolvedRecord(
            message_id=row["id"],
            source=row["source"],
            category=Category(row["category"]) if row["category"] else None,
            urgency=Urgency(row["urgency"]) if row["urgency"] else None,
            request_type=RequestType(row["request_type"]) if row["request_type"] else None,
            asks_user_to_act=bool(row["asks_user_to_act"]) if row["asks_user_to_act"] is not None else None,
            trust=TrustLabel(row["trust"]),
            trust_reasons=[TrustReason(r) for r in json.loads(row["trust_reasons"])],
            deadline=_parse_iso(row["deadline"]),
            amount=amount,
            evidence_refs=json.loads(row["evidence"]),
            unparsed=bool(row["unparsed"]),
        )

    def get_brief_data(self, message_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
        if row is None:
            return None
        return dict(row)

    def all_brief_rows(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM messages ORDER BY ts").fetchall()
        return [dict(row) for row in rows]

    def create_proposal(self, message_id: str, kind: str) -> int:
        cursor = self._conn.execute(
            "INSERT INTO proposals (message_id, kind, status, created_at) VALUES (?, ?, 'pending', ?)",
            (message_id, kind, datetime.now().isoformat()),
        )
        self._conn.commit()
        return cursor.lastrowid

    def list_proposals(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM proposals ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def approve_proposal(self, proposal_id: int) -> bool:
        cursor = self._conn.execute(
            "UPDATE proposals SET status = 'approved' WHERE id = ? AND status = 'pending'",
            (proposal_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0
