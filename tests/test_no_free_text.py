"""Structural guarantee: no free-text field exists in the quarantine schema."""

from __future__ import annotations

from typing import Any

from airlock.schema import ollama_schema


def _walk(node: Any) -> list[dict[str, Any]]:
    """Return every schema node for inspection."""
    nodes: list[dict[str, Any]] = []
    if isinstance(node, dict):
        nodes.append(node)
        for value in node.values():
            nodes.extend(_walk(value))
    elif isinstance(node, list):
        for item in node:
            nodes.extend(_walk(item))
    return nodes


def test_no_free_text_string_fields() -> None:
    schema = ollama_schema()
    for node in _walk(schema):
        if node.get("type") == "string":
            assert "enum" in node, f"string field without enum: {node}"


def test_schema_is_flat() -> None:
    schema = ollama_schema()
    assert "$ref" not in schema
    assert "$defs" not in schema


def test_schema_has_expected_shape() -> None:
    schema = ollama_schema()
    assert schema.get("type") == "object"
    assert schema.get("additionalProperties") is False
    required = set(schema.get("required", []))
    assert {"category", "urgency", "request_type", "asks_user_to_act"} <= required
