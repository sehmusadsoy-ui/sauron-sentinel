"""Strict, declarative TOML detection rules; no executable expressions."""

from __future__ import annotations

import math
import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from .models import Event, ValidationError

_MISSING = object()
_FIELD = re.compile(
    r"(?:source|kind|device_id|synthetic|attributes\.[A-Za-z_][A-Za-z0-9_]{0,63})\Z"
)
_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_RULE_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_MAX_CONFIG_BYTES = 262_144


def field_value(event: Event, field: str) -> Any:
    """Resolve one allowlisted field without traversing arbitrary objects."""
    if field.startswith("attributes."):
        return event.attributes.get(field[11:], _MISSING)
    return getattr(event, field)


def is_number(value: Any) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: Any

    def matches(self, event: Event) -> bool:
        actual = field_value(event, self.field)
        if actual is _MISSING:
            return False
        if self.op in ("eq", "ne"):
            compatible = type(actual) is type(self.value) or (
                is_number(actual) and is_number(self.value)
            )
            equal = compatible and actual == self.value
            return equal if self.op == "eq" else compatible and not equal
        if not is_number(actual):
            return False
        if self.op == "gt":
            return actual > self.value
        if self.op == "gte":
            return actual >= self.value
        if self.op == "lt":
            return actual < self.value
        return actual <= self.value


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    kind: str
    threshold: int = 1
    window_seconds: float = 60
    cooldown_seconds: float = 60
    group_by: tuple[str, ...] = ("device_id",)
    conditions: tuple[Condition, ...] = ()

    def matches(self, event: Event) -> bool:
        return event.kind == self.kind and all(c.matches(event) for c in self.conditions)


def _fail(message: str) -> None:
    raise ValidationError(f"Invalid rules: {message}")


def _duration(data: dict[str, Any], name: str, default: int, zero: bool = False) -> float:
    value = data.get(name, default)
    if not is_number(value) or not (0 <= value <= 86_400) or (not zero and value == 0):
        _fail(f"{name} must be {'0..86400' if zero else '>0..86400'} seconds")
    return float(value)


def _field(value: Any) -> str:
    if not isinstance(value, str) or not _FIELD.fullmatch(value):
        _fail("field must be source, kind, device_id, synthetic or attributes.<key>")
    return value


def _condition(data: Any) -> Condition:
    if not isinstance(data, dict) or set(data) != {"field", "op", "value"}:
        _fail("each condition requires exactly field, op and value")
    field = _field(data["field"])
    op, value = data["op"], data["value"]
    if op not in ("eq", "ne", "gt", "gte", "lt", "lte"):
        _fail("unsupported condition operator")
    if not (value is None or type(value) in (str, bool, int, float)):
        _fail("condition value must be a scalar")
    if isinstance(value, str) and len(value) > 1024:
        _fail("condition string is too long")
    if type(value) in (int, float) and not is_number(value):
        _fail("condition numbers must be finite")
    if op not in ("eq", "ne") and not is_number(value):
        _fail("ordered comparisons require a finite number")
    return Condition(field, op, value)


def _rule(data: Any) -> Rule:
    allowed = {
        "id",
        "title",
        "severity",
        "kind",
        "threshold",
        "window_seconds",
        "cooldown_seconds",
        "group_by",
        "conditions",
    }
    required = {"id", "title", "severity", "kind"}
    if not isinstance(data, dict) or not required <= set(data) or set(data) - allowed:
        _fail("rule has unknown keys or missing id/title/severity/kind")
    if not isinstance(data["id"], str) or not _RULE_ID.fullmatch(data["id"]):
        _fail("rule id must be a lowercase slug, at most 64 characters")
    if not isinstance(data["title"], str) or not 1 <= len(data["title"]) <= 160:
        _fail("rule title must have 1..160 characters")
    if data["severity"] not in ("low", "medium", "high", "critical"):
        _fail("unsupported severity")
    if not isinstance(data["kind"], str) or not _TOKEN.fullmatch(data["kind"]):
        _fail("kind must be a lowercase token, at most 64 characters")
    threshold = data.get("threshold", 1)
    if type(threshold) is not int or not 1 <= threshold <= 10_000:
        _fail("threshold must be an integer in 1..10000")
    group_by = data.get("group_by", ["device_id"])
    if not isinstance(group_by, list) or not 1 <= len(group_by) <= 8:
        _fail("group_by must contain 1..8 fields")
    groups = tuple(_field(f) for f in group_by)
    if len(set(groups)) != len(groups):
        _fail("duplicate group_by fields")
    conditions = data.get("conditions", [])
    if not isinstance(conditions, list) or len(conditions) > 16:
        _fail("conditions must be a list with at most 16 entries")
    return Rule(
        id=data["id"],
        title=data["title"],
        severity=data["severity"],
        kind=data["kind"],
        threshold=threshold,
        window_seconds=_duration(data, "window_seconds", 60),
        cooldown_seconds=_duration(data, "cooldown_seconds", 60, zero=True),
        group_by=groups,
        conditions=tuple(_condition(c) for c in conditions),
    )


def load_rules(path: Path | None = None) -> list[Rule]:
    """Load validated rules from a local file or the bundled demonstration rules."""
    try:
        if path is None:
            payload = resources.files("sauron_sentinel").joinpath("defaults.toml").read_bytes()
        else:
            with Path(path).open("rb") as stream:
                payload = stream.read(_MAX_CONFIG_BYTES + 1)
        if len(payload) > _MAX_CONFIG_BYTES:
            _fail("configuration exceeds 256 KiB")
        data = tomllib.loads(payload.decode("utf-8"))
    except RecursionError as exc:
        raise ValidationError("Cannot load rules: TOML nesting is too deep") from exc
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError(f"Cannot load rules: {exc}") from exc
    if set(data) != {"schema_version", "rules"} or type(data["schema_version"]) is not int:
        _fail("expected schema_version and rules only")
    if data["schema_version"] != 1:
        _fail("unsupported schema_version")
    entries = data["rules"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
        _fail("expected 1..64 rules")
    rules = [_rule(entry) for entry in entries]
    if len({rule.id for rule in rules}) != len(rules):
        _fail("duplicate rule id")
    return rules
