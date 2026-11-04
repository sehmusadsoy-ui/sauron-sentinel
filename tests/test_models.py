"""Telemetry contracts are strict, deterministic, and timezone independent."""

import math
from datetime import UTC

import pytest

from sauron_sentinel.models import ValidationError, normalize


def test_normalize_equivalent_timezones_and_roundtrip(record):
    first = normalize(record())
    second = normalize(record(timestamp="2026-01-01T03:00:00+03:00"))
    assert first.timestamp.tzinfo == UTC
    assert first.event_id == second.event_id
    assert len(first.event_id) == 64
    assert normalize(first.to_dict()).to_dict() == first.to_dict()


def test_identifier_changes_with_payload(record):
    assert normalize(record()).event_id != normalize(record(device_id="host-02")).event_id
    assert normalize(record()).event_id != normalize(record(synthetic=False)).event_id


def test_attribute_key_order_does_not_change_identifier(record):
    a = normalize(record(attributes={"user": "alice", "score": 0.5}))
    b = normalize(record(attributes={"score": 0.5, "user": "alice"}))
    assert a.event_id == b.event_id


def test_normalization_detaches_mutable_input(record):
    raw = record()
    event = normalize(raw)
    raw["attributes"]["user"] = "changed"
    assert event.attributes["user"] == "alice"
    with pytest.raises(TypeError):
        event.attributes["user"] = "changed"


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"timestamp": "2026-01-01T00:00:00"},
        {"timestamp": "not-a-date"},
        {"timestamp": 123},
        {"source": ""},
        {"source": "bad\nsource"},
        {"kind": ""},
        {"device_id": ""},
        {"synthetic": "true"},
        {"synthetic": 1},
        {"attributes": []},
        {"attributes": {"nested": {"value": 1}}},
        {"attributes": {"list": [1]}},
        {"attributes": {"score": math.nan}},
        {"attributes": {"score": math.inf}},
        {"unknown": "field"},
        {"event_id": "0" * 64},
    ],
)
def test_rejects_invalid_records(record, changes):
    with pytest.raises(ValidationError):
        normalize(record(**changes))


@pytest.mark.parametrize(
    "missing", ["schema_version", "timestamp", "source", "kind", "device_id", "synthetic"]
)
def test_required_fields(record, missing):
    raw = record()
    del raw[missing]
    with pytest.raises(ValidationError):
        normalize(raw)


@pytest.mark.parametrize("value", [None, [], "text", 4, True])
def test_top_level_must_be_object(value):
    with pytest.raises(ValidationError):
        normalize(value)


def test_code_like_attribute_is_plain_data(record):
    expression = "__import__('os').system('do-not-execute')"
    event = normalize(record(attributes={"user": expression, "nullable": None}))
    assert event.attributes["user"] == expression
    assert event.attributes["nullable"] is None


def test_timestamp_precision_is_preserved_without_silent_truncation(record):
    first = normalize(record(timestamp="2026-01-01T00:00:00.123456Z"))
    second = normalize(record(timestamp="2026-01-01T00:00:00.123457Z"))
    assert first.timestamp.microsecond == 123456
    assert first.event_id != second.event_id
    with pytest.raises(ValidationError):
        normalize(record(timestamp="2026-01-01T00:00:00.1234567Z"))
