"""Self-validation tests for the property and schema-escape checks."""

from __future__ import annotations

from airlock.extractor import MockAdapter

from eval.property_tests import run_cross_message_test
from eval.schema_escape import FixedAdapter, run_schema_escape


def test_cross_message_isolation_is_stable_with_mock():
    result = run_cross_message_test(n=30, quarantine_model="mock")
    assert result["n"] >= 20
    assert result["changed_with_attack"] == 0
    assert result["stable"] is True


def test_schema_escape_mock_adapter_is_always_valid():
    result = run_schema_escape(MockAdapter(), n=30)
    assert result["schema_valid_rate"] == 1.0
    assert result["not_json"] == 0
    assert result["invalid_schema"] == 0


def test_schema_escape_detects_out_of_schema_output():
    adapter = FixedAdapter('{"category":"nonsense","urgency":"high","request_type":"payment"}')
    result = run_schema_escape(adapter, n=10)
    assert result["schema_valid_rate"] == 0.0
    assert result["out_of_vocabulary"] == 10


def test_schema_escape_detects_non_json_output():
    adapter = FixedAdapter("I cannot comply.")
    result = run_schema_escape(adapter, n=10)
    assert result["schema_valid_rate"] == 0.0
    assert result["not_json"] == 10
