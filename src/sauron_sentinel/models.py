"""Versioned, bounded telemetry with stable content-derived identifiers."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType

Scalar = str | int | float | bool | None
_LABEL = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_DEVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_FIELDS = {
    "schema_version",
    "timestamp",
    "source",
    "kind",
    "device_id",
    "synthetic",
    "attributes",
}


class ValidationError(ValueError):
    """Input cannot be safely interpreted under the supported contract."""


def format_timestamp(value: datetime) -> str:
    """Render a UTC timestamp without losing microsecond precision."""
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class Event:
    """A normalized observation, not an assertion of a security incident."""

    event_id: str
    timestamp: datetime
    source: str
    kind: str
    device_id: str
    synthetic: bool
    attributes: Mapping[str, Scalar]

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "event_id": self.event_id,
            "timestamp": format_timestamp(self.timestamp),
            "source": self.source,
            "kind": self.kind,
            "device_id": self.device_id,
            "synthetic": self.synthetic,
            "attributes": dict(self.attributes),
        }


def normalize(record: dict) -> Event:
    """Validate a v1 record and normalize its time to UTC.

    Attribute values are intentionally flat JSON scalars. Strings are never
    interpreted as code, templates, paths, or commands.
    """
    if not isinstance(record, dict):
        raise ValidationError("event must be a JSON object")
    if not _FIELDS <= record.keys() or record.keys() - (_FIELDS | {"event_id"}):
        raise ValidationError("event has missing or unknown fields")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise ValidationError("schema_version must be integer 1")
    for field in ("source", "kind", "device_id"):
        pattern = _DEVICE if field == "device_id" else _LABEL
        if not isinstance(record[field], str) or not pattern.fullmatch(record[field]):
            raise ValidationError(f"{field} has invalid format or length")
    if type(record["synthetic"]) is not bool:
        raise ValidationError("synthetic must be an explicit boolean")
    raw_time = record["timestamp"]
    if not isinstance(raw_time, str) or not _TIMESTAMP.fullmatch(raw_time):
        raise ValidationError(
            "timestamp requires YYYY-MM-DDTHH:MM:SS[.1..6 digits] and Z or +/-HH:MM"
        )
    try:
        stamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError("timezone required")
        stamp = stamp.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ValidationError("timestamp must be a valid offset-aware ISO 8601 time") from exc
    attrs = record["attributes"]
    if not isinstance(attrs, dict) or len(attrs) > 32:
        raise ValidationError("attributes must be an object with at most 32 fields")
    for key, value in attrs.items():
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise ValidationError("attribute key has invalid format or length")
        if value is not None and type(value) not in (str, int, float, bool):
            raise ValidationError("attributes must contain only JSON scalar values")
        if isinstance(value, str) and len(value) > 1024:
            raise ValidationError("attribute string exceeds 1024 characters")
        if type(value) is float and not math.isfinite(value):
            raise ValidationError("attribute numbers must be finite")
        if type(value) is int and abs(value) > 2**53 - 1:
            raise ValidationError("attribute integer exceeds interoperable JSON range")
    canonical = {
        "schema_version": 1,
        "timestamp": format_timestamp(stamp),
        "source": record["source"],
        "kind": record["kind"],
        "device_id": record["device_id"],
        "synthetic": record["synthetic"],
        "attributes": dict(attrs),
    }
    event_id = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    ).hexdigest()
    if "event_id" in record and record["event_id"] != event_id:
        raise ValidationError("event_id does not match normalized content")
    return Event(
        event_id=event_id,
        timestamp=stamp,
        source=record["source"],
        kind=record["kind"],
        device_id=record["device_id"],
        synthetic=record["synthetic"],
        attributes=MappingProxyType(dict(attrs)),
    )
