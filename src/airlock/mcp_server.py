"""Read-only MCP server.

Exposes typed records to other open-source agents. The server never returns sender
strings or quote text; every value is an enum, a number, a boolean, or a resolved
date/amount produced by deterministic code.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from .models import TrustLabel
from .schema import Category, Urgency
from .store import Store

_ALLOWED_ACTIONS = {"calendar", "archive", "flag"}


def _build_server(db: str) -> MCPServer:
    store = Store(db)
    server = MCPServer(name="airlock", description="Read-only typed inbox records from Airlock.")

    @server.tool()
    def list_messages(
        trust: str | None = None,
        category: str | None = None,
        min_urgency: str | None = None,
    ) -> list[dict]:
        """List typed message records, optionally filtered by trust, category, or urgency."""
        records = store.list_records(
            trust=TrustLabel(trust) if trust else None,
            category=Category(category) if category else None,
            min_urgency=Urgency(min_urgency) if min_urgency else None,
        )
        return [record.model_dump(mode="json") for record in records]

    @server.tool()
    def get_message(message_id: str) -> dict:
        """Return one typed message record plus evidence sentence indices. No quote text."""
        record = store.get_record(message_id)
        if record is None:
            return {"error": "not_found"}
        return record.model_dump(mode="json")

    @server.tool()
    def propose_action(message_id: str, kind: str) -> dict:
        """Queue a pending action proposal that must be approved by a human locally."""
        if kind not in _ALLOWED_ACTIONS:
            return {"error": "invalid_action", "allowed": sorted(_ALLOWED_ACTIONS)}
        if store.get_record(message_id) is None:
            return {"error": "not_found"}
        proposal_id = store.create_proposal(message_id, kind)
        return {"proposal_id": proposal_id, "status": "pending"}

    return server


def serve(db: str) -> None:
    _build_server(db).run(transport="stdio")
