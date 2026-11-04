"""Bounded event-time correlation with deterministic, explainable evidence."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict, deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

from .models import Event, ValidationError, format_timestamp
from .rules import _MISSING, Rule, field_value


@dataclass(frozen=True)
class Alert:
    alert_id: str
    rule_id: str
    title: str
    severity: str
    timestamp: datetime
    window_start: datetime
    window_end: datetime
    matched_count: int
    event_ids: tuple[str, ...]
    group: Mapping[str, Any]
    synthetic: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "timestamp": format_timestamp(self.timestamp),
            "window_start": format_timestamp(self.window_start),
            "window_end": format_timestamp(self.window_end),
            "matched_count": self.matched_count,
            "event_ids": list(self.event_ids),
            "group": dict(self.group),
            "synthetic": self.synthetic,
        }


@dataclass
class _State:
    rule: Rule
    group: dict[str, Any]
    evidence: deque[tuple[datetime, str]] = field(default_factory=deque)
    last_alert: datetime | None = None


class RuleEngine:
    """Process a single ordered stream; instantiate anew for each independent replay.

    The evidence count saturates at each rule's threshold. Duplicate suppression is
    bounded to the most recently accepted IDs, not a durable exactly-once guarantee.
    """

    def __init__(
        self,
        rules: list[Rule],
        max_groups: int = 4096,
        dedup_capacity: int = 10_000,
        max_evidence: int = 100_000,
    ) -> None:
        if not rules or len(rules) > 64 or len({r.id for r in rules}) != len(rules):
            raise ValidationError("Engine requires 1..64 rules with unique IDs")
        if type(max_groups) is not int or not 1 <= max_groups <= 65_536:
            raise ValidationError("max_groups must be an integer in 1..65536")
        if type(dedup_capacity) is not int or not 1 <= dedup_capacity <= 1_000_000:
            raise ValidationError("dedup_capacity must be an integer in 1..1000000")
        if type(max_evidence) is not int or not 1 <= max_evidence <= 1_000_000:
            raise ValidationError("max_evidence must be an integer in 1..1000000")
        self.rules = tuple(rules)
        self.max_groups = max_groups
        self.dedup_capacity = dedup_capacity
        self.max_evidence = max_evidence
        self._evidence_count = 0
        self._states: dict[tuple[Any, ...], _State] = {}
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._watermark: datetime | None = None

    def _prune(self, timestamp: datetime) -> None:
        expired = []
        for key, state in self._states.items():
            while (
                state.evidence
                and (timestamp - state.evidence[0][0]).total_seconds() > state.rule.window_seconds
            ):
                state.evidence.popleft()
                self._evidence_count -= 1
            cooling = (
                state.last_alert is not None
                and (timestamp - state.last_alert).total_seconds() < state.rule.cooldown_seconds
            )
            if not state.evidence and not cooling:
                expired.append(key)
        for key in expired:
            del self._states[key]

    def process(self, event: Event) -> list[Alert]:
        """Accept one event or raise on disorder/capacity; return zero or more alerts."""
        if self._watermark is not None and event.timestamp < self._watermark:
            raise ValidationError("Events must be ordered by nondecreasing timestamp")
        if event.event_id in self._seen:
            self._seen.move_to_end(event.event_id)
            return []
        self._prune(event.timestamp)
        matches = []
        for rule in self.rules:
            if not rule.matches(event):
                continue
            group = {name: field_value(event, name) for name in rule.group_by}
            if any(value is _MISSING for value in group.values()):
                continue
            typed = tuple((type(value).__name__, value) for value in group.values())
            key = (rule.id, event.synthetic, typed)
            matches.append((key, rule, group))
        new_groups = sum(key not in self._states for key, _, _ in matches)
        if len(self._states) + new_groups > self.max_groups:
            raise ValidationError(
                "Active detection group limit reached; narrow rules or split input"
            )
        additional_evidence = sum(
            key not in self._states or len(self._states[key].evidence) < rule.threshold
            for key, rule, _ in matches
        )
        if self._evidence_count + additional_evidence > self.max_evidence:
            raise ValidationError("Active evidence limit reached; narrow rules or split input")
        self._watermark = event.timestamp
        self._seen[event.event_id] = None
        if len(self._seen) > self.dedup_capacity:
            self._seen.popitem(last=False)
        alerts = []
        for key, rule, group in matches:
            if key not in self._states:
                self._states[key] = _State(rule, group, deque(maxlen=rule.threshold))
            state = self._states[key]
            if len(state.evidence) < rule.threshold:
                self._evidence_count += 1
            state.evidence.append((event.timestamp, event.event_id))
            cooling = (
                state.last_alert is not None
                and (event.timestamp - state.last_alert).total_seconds() < rule.cooldown_seconds
            )
            if len(state.evidence) < rule.threshold or cooling:
                continue
            evidence_ids = tuple(item[1] for item in state.evidence)
            identity = json.dumps(
                [rule.id, event.synthetic, group, evidence_ids],
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            alerts.append(
                Alert(
                    alert_id=hashlib.sha256(identity).hexdigest(),
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    timestamp=event.timestamp,
                    window_start=state.evidence[0][0],
                    window_end=event.timestamp,
                    matched_count=len(state.evidence),
                    event_ids=evidence_ids,
                    group=MappingProxyType(dict(group)),
                    synthetic=event.synthetic,
                )
            )
            state.last_alert = event.timestamp
        return alerts
