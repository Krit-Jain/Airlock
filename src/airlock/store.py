"""Local SQLite store.

The store is the only place sanitized message text and quote text live on disk. Typed
records are exposed to MCP clients; raw and sanitized text are kept local for the brief.
Processing is resumable because every message is keyed by a content hash.
"""

from __future__ import annotations

import functools
import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Message, ResolvedAmount, ResolvedRecord, TrustLabel, TrustReason, message_id_for
from .schema import Category, RequestType, Urgency


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _parse_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _locked(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
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
                section TEXT NOT NULL,
                model_tag TEXT,
                schema_hash TEXT,
                prompt_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS staged (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                sender TEXT NOT NULL,
                ts TEXT,
                raw_text TEXT NOT NULL,
                headers TEXT NOT NULL
            );
            """
        )
        self._conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created."""
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(messages)").fetchall()}
        for name in ("model_tag", "schema_hash", "prompt_hash"):
            if name not in columns:
                self._conn.execute(f"ALTER TABLE messages ADD COLUMN {name} TEXT")
        self._conn.commit()

    @_locked
    def close(self) -> None:
        self._conn.close()

    @_locked
    def is_processed(self, message_id: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM messages WHERE id = ?", (message_id,)).fetchone()
        return row is not None

    @_locked
    def is_cached(self, message_id: str, model_tag: str, schema_hash: str, prompt_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM messages WHERE id = ? AND model_tag = ? AND schema_hash = ? AND prompt_hash = ?",
            (message_id, model_tag, schema_hash, prompt_hash),
        ).fetchone()
        return row is not None

    @_locked
    def stage_messages(self, messages: list[Message]) -> None:
        for message in messages:
            self._conn.execute(
                "INSERT OR REPLACE INTO staged (id, source, sender, ts, raw_text, headers) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    message.id,
                    message.source,
                    message.sender,
                    _iso(message.ts),
                    message.raw_text,
                    json.dumps(message.headers),
                ),
            )
        self._conn.commit()

    @_locked
    def staged_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM staged").fetchone()[0]

    @_locked
    def staged_messages(self, limit: int | None = None) -> list[Message]:
        query = "SELECT * FROM staged"
        params: list[Any] = []
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [
            Message(
                id=row["id"],
                source=row["source"],
                sender=row["sender"],
                ts=_parse_iso(row["ts"]),
                raw_text=row["raw_text"],
                headers=json.loads(row["headers"]),
            )
            for row in rows
        ]

    @_locked
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
        model_tag: str = "",
        schema_hash: str = "",
        prompt_hash: str = "",
    ) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO messages (
                id, source, sender, ts, raw_text, sanitized_text, sentences, headers,
                trust, trust_reasons, category, urgency, request_type, asks_user_to_act,
                evidence, deadline_sentence, amount_sentence, deadline, amount_value,
                amount_currency, unparsed, disputed, section, model_tag, schema_hash, prompt_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                model_tag,
                schema_hash,
                prompt_hash,
            ),
        )
        self._conn.commit()

    @_locked
    def get_record(self, message_id: str) -> ResolvedRecord | None:
        row = self._conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    @_locked
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

    @_locked
    def get_brief_data(self, message_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
        if row is None:
            return None
        return dict(row)

    @_locked
    def all_brief_rows(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM messages ORDER BY ts").fetchall()
        return [dict(row) for row in rows]

    @_locked
    def create_proposal(self, message_id: str, kind: str) -> int:
        cursor = self._conn.execute(
            "INSERT INTO proposals (message_id, kind, status, created_at) VALUES (?, ?, 'pending', ?)",
            (message_id, kind, datetime.now().isoformat()),
        )
        self._conn.commit()
        return cursor.lastrowid

    @_locked
    def list_proposals(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM proposals ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    @_locked
    def approve_proposal(self, proposal_id: int) -> bool:
        cursor = self._conn.execute(
            "UPDATE proposals SET status = 'approved' WHERE id = ? AND status = 'pending'",
            (proposal_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0
