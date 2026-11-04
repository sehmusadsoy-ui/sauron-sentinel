"""Behavioral detection tests use event time and independently authored rules."""

import pytest

from sauron_sentinel.engine import RuleEngine
from sauron_sentinel.models import ValidationError, normalize
from sauron_sentinel.rules import load_rules


def test_window_boundary_and_evidence_are_inclusive(record, rules_file):
    engine = RuleEngine(load_rules(rules_file()))
    first, last = normalize(record(0)), normalize(record(10))
    assert engine.process(first) == []
    alerts = engine.process(last)
    assert len(alerts) == 1
    alert = alerts[0].to_dict()
    assert alert["event_ids"] == [first.event_id, last.event_id]
    assert alert["matched_count"] == 2
    assert alert["synthetic"] is True
    assert alert["rule_id"] == "test-rule"
    assert alert["severity"] == "medium"


def test_expired_event_does_not_satisfy_threshold(record, rules_file):
    engine = RuleEngine(load_rules(rules_file()))
    assert engine.process(normalize(record(0))) == []
    assert engine.process(normalize(record(11))) == []
    assert len(engine.process(normalize(record(12)))) == 1


def test_cooldown_suppresses_until_exact_boundary(record, rules_file):
    engine = RuleEngine(load_rules(rules_file(threshold=1, window=30, cooldown=20)))
    assert len(engine.process(normalize(record(0)))) == 1
    assert engine.process(normalize(record(19))) == []
    assert len(engine.process(normalize(record(20)))) == 1


def test_duplicate_id_cannot_manufacture_a_burst(record, rules_file):
    engine = RuleEngine(load_rules(rules_file()))
    first = normalize(record(0))
    assert engine.process(first) == []
    assert engine.process(first) == []
    assert len(engine.process(normalize(record(1)))) == 1


def test_device_and_user_groups_are_independent(record, rules_file):
    engine = RuleEngine(load_rules(rules_file()))
    for seconds, user, device in [(0, "alice", "a"), (1, "bob", "a"), (2, "alice", "b")]:
        assert (
            engine.process(normalize(record(seconds, device_id=device, attributes={"user": user})))
            == []
        )
    assert (
        len(engine.process(normalize(record(3, device_id="a", attributes={"user": "alice"})))) == 1
    )


def test_real_and_synthetic_evidence_never_mix(record, rules_file):
    engine = RuleEngine(load_rules(rules_file()))
    assert engine.process(normalize(record(0, synthetic=True))) == []
    assert engine.process(normalize(record(1, synthetic=False))) == []
    alerts = engine.process(normalize(record(2, synthetic=True)))
    assert len(alerts) == 1
    assert alerts[0].to_dict()["synthetic"] is True


def test_out_of_order_event_fails_closed(record, rules_file):
    engine = RuleEngine(load_rules(rules_file()))
    engine.process(normalize(record(10)))
    with pytest.raises(ValidationError):
        engine.process(normalize(record(9)))


def test_unmatched_kind_never_increments_threshold(record, rules_file):
    engine = RuleEngine(load_rules(rules_file()))
    assert engine.process(normalize(record(0, kind="system.heartbeat"))) == []
    assert engine.process(normalize(record(1))) == []


def test_missing_condition_attribute_is_not_a_match(record, rules_file):
    engine = RuleEngine(
        load_rules(
            rules_file(
                threshold=1,
                conditions='{field="attributes.score", op="gte", value=0.8}',
            )
        )
    )
    assert engine.process(normalize(record())) == []


@pytest.mark.parametrize(
    ("operator", "value", "matches"),
    [
        ("gt", 0.9, True),
        ("gte", 0.8, True),
        ("lt", 0.7, True),
        ("lte", 0.8, True),
        ("eq", 0.8, True),
        ("ne", 0.9, True),
        ("gt", 0.8, False),
        ("lt", 0.8, False),
        ("eq", 0.9, False),
        ("gte", True, False),
        ("eq", True, False),
        ("gte", "0.9", False),
    ],
)
def test_condition_operators_do_not_coerce_types(record, rules_file, operator, value, matches):
    engine = RuleEngine(
        load_rules(
            rules_file(
                threshold=1,
                conditions=f'{{field="attributes.score", op="{operator}", value=0.8}}',
            )
        )
    )
    alerts = engine.process(normalize(record(attributes={"user": "alice", "score": value})))
    assert bool(alerts) is matches


def test_group_limit_fails_closed_and_expired_groups_are_reclaimed(record, rules_file):
    rules = load_rules(rules_file())
    engine = RuleEngine(rules, max_groups=1)
    engine.process(normalize(record(0, device_id="a")))
    with pytest.raises(ValidationError):
        engine.process(normalize(record(1, device_id="b")))
    assert engine.process(normalize(record(40, device_id="b"))) == []


def test_alert_ids_are_reproducible(record, rules_file):
    rules = load_rules(rules_file())
    results = []
    for _ in range(2):
        engine = RuleEngine(rules)
        engine.process(normalize(record(0)))
        results.append(engine.process(normalize(record(1)))[0].to_dict())
    assert results[0] == results[1]


def test_global_evidence_limit_fails_closed_then_recovers_after_expiry(record, rules_file):
    engine = RuleEngine(load_rules(rules_file()), max_evidence=1)
    assert engine.process(normalize(record(0))) == []
    with pytest.raises(ValidationError):
        engine.process(normalize(record(1)))
    assert engine.process(normalize(record(40))) == []
