"""Reusable synthetic telemetry and isolated rule configuration."""

from datetime import UTC, datetime, timedelta

import pytest


@pytest.fixture
def record():
    def make(seconds=0, **changes):
        timestamp = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
        value = {
            "schema_version": 1,
            "timestamp": timestamp.isoformat(),
            "source": "test-lab",
            "kind": "auth.failure",
            "device_id": "host-01",
            "synthetic": True,
            "attributes": {"user": "alice", "attempt": seconds},
        }
        value.update(changes)
        return value

    return make


@pytest.fixture
def rules_file(tmp_path):
    def make(*, threshold=2, window=10, cooldown=20, conditions="", group_by=None):
        groups = group_by or '["device_id", "attributes.user"]'
        path = tmp_path / "rules.toml"
        path.write_text(
            f"""schema_version = 1
[[rules]]
id = "test-rule"
title = "Test observation"
severity = "medium"
kind = "auth.failure"
threshold = {threshold}
window_seconds = {window}
cooldown_seconds = {cooldown}
group_by = {groups}
conditions = [{conditions}]
""",
            encoding="utf-8",
        )
        return path

    return make
