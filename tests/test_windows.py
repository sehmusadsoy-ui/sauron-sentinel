"""Windows collector contracts without depending on host logs or permissions."""

from __future__ import annotations

import base64
import json
import subprocess
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sauron_sentinel import windows
from sauron_sentinel.models import ValidationError

SINCE = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def payload():
    return {
        "sources": [
            {"channel": channel, "status": "ok", "event_count": 0, "limit_reached": False}
            for channel in windows.CHANNELS
        ],
        "records": [],
    }


@pytest.fixture
def record():
    return {
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_id": 4625,
        "record_id": 42,
        "timestamp": "2026-01-01T01:00:00.123456Z",
        "data": {"user": "test-user", "target_user": "test-user", "logon_type": "3"},
        "fields_truncated": False,
    }


def _mock_collect(monkeypatch, payload):
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows, "_powershell", lambda: "powershell.exe")
    monkeypatch.setattr(windows, "_run_powershell", lambda *args: json.dumps(payload).encode())


def test_real_source_normalized_ordered_stable_and_allowlisted(monkeypatch, payload, record):
    later = dict(record, record_id=43, timestamp="2026-01-01T02:00:00.000000Z")
    record["data"]["Message"] = "must not be retained"
    record["data"]["service_path"] = "must not be retained"
    payload["records"] = [later, record, record]
    _mock_collect(monkeypatch, payload)
    first = windows.collect_windows(SINCE)
    second = windows.collect_windows(SINCE)
    assert len(first.events) == 2
    assert first.events == second.events
    event = first.events[0]
    assert event.kind == "auth.failure"
    assert event.source == "windows-eventlog"
    assert event.synthetic is False
    assert event.timestamp < first.events[1].timestamp
    assert event.device_id.startswith("windows-")
    assert len(event.device_id) == 24
    assert event.attributes["logon_type"] == 3
    assert event.attributes["record_id"] == 42
    assert "Message" not in event.attributes
    assert "service_path" not in event.attributes
    assert first.sources[1]["event_count"] == 2


@pytest.mark.parametrize(
    ("channel", "event_id", "provider", "kind"),
    [
        (channel, event_id, windows._PROVIDERS[definition[0]], definition[1])
        for (channel, event_id), definition in windows._EVENT_TYPES.items()
    ],
)
def test_supported_ids_require_provider(record, channel, event_id, provider, kind):
    record.update(channel=channel, event_id=event_id, provider=provider)
    assert windows._record_event(record, "windows-test").kind == kind
    record["provider"] = "another-provider"
    assert windows._record_event(record, "windows-test") is None


def test_unrecognized_events_are_ignored(record):
    record["event_id"] = 9999
    assert windows._record_event(record, "windows-test") is None


def test_unavailable_is_distinct_from_empty_channel(monkeypatch, payload):
    payload["sources"][1].update(status="unavailable", error="permission_denied")
    _mock_collect(monkeypatch, payload)
    batch = windows.collect_windows(SINCE)
    assert batch.events == []
    assert batch.sources[0] == {
        "channel": "System",
        "status": "ok",
        "event_count": 0,
        "limit_reached": False,
    }
    assert batch.sources[1]["status"] == "unavailable"
    assert batch.sources[1]["error"] == "permission_denied"
    assert "error" not in batch.sources[2]


def test_truncation_signal_preserved(monkeypatch, payload, record):
    payload["records"] = [record]
    payload["sources"][1]["limit_reached"] = True
    record["fields_truncated"] = True
    _mock_collect(monkeypatch, payload)
    batch = windows.collect_windows(SINCE, limit=1)
    assert batch.sources[1]["limit_reached"] is True
    assert batch.events[0].attributes["fields_truncated"] is True


@pytest.mark.parametrize("value", [0, -1, True, 1001, 1.5, "5"])
def test_invalid_limit(value):
    with pytest.raises(ValidationError):
        windows.collect_windows(SINCE, value)


@pytest.mark.parametrize("value", [None, "2026-01-01", datetime(2026, 1, 1)])
def test_invalid_since(value):
    with pytest.raises(ValidationError):
        windows.collect_windows(value)


def test_since_utc_overflow_is_a_validation_failure():
    since = datetime.min.replace(tzinfo=timezone(timedelta(hours=1)))
    with pytest.raises(ValidationError, match="represented in UTC"):
        windows.collect_windows(since)


def test_non_windows_availability(monkeypatch):
    monkeypatch.setattr(windows.platform, "system", lambda: "Linux")
    batch = windows.collect_windows(SINCE)
    assert not batch.events
    assert all(s["status"] == "unavailable" and s["error"] == "not_windows" for s in batch.sources)


def test_no_powershell_availability(monkeypatch):
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows, "_powershell", lambda: None)
    batch = windows.collect_windows(SINCE)
    assert all(s["error"] == "powershell_unavailable" for s in batch.sources)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (subprocess.TimeoutExpired("powershell", 30), "timeout"),
        (OSError("private diagnostic"), "collection_failed"),
        (ValueError("private diagnostic"), "invalid_response"),
    ],
)
def test_failures_are_generic(monkeypatch, error, expected):
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows, "_powershell", lambda: "powershell.exe")

    def fail(*args):
        raise error

    monkeypatch.setattr(windows, "_run_powershell", fail)
    batch = windows.collect_windows(SINCE)
    assert all(s["status"] == "error" and s["error"] == expected for s in batch.sources)
    assert "private diagnostic" not in str(batch.sources)


@pytest.mark.parametrize("raw", [b"not-json", b"\xff", b"[]", b"{}"])
def test_bad_response(monkeypatch, raw):
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows, "_powershell", lambda: "powershell.exe")
    monkeypatch.setattr(windows, "_run_powershell", lambda *args: raw)
    assert windows.collect_windows(SINCE).sources[0]["error"] == "invalid_response"


@pytest.mark.parametrize(
    "change", ["unknown_channel", "duplicate_source", "too_many", "bad_status"]
)
def test_invalid_source_or_count(monkeypatch, payload, record, change):
    if change == "unknown_channel":
        payload["records"] = [dict(record, channel="private-channel")]
    elif change == "duplicate_source":
        payload["sources"][2] = dict(payload["sources"][0])
    elif change == "too_many":
        payload["records"] = [record] * 4
    else:
        payload["sources"][0]["status"] = "private-status"
    _mock_collect(monkeypatch, payload)
    assert windows.collect_windows(SINCE, limit=1).sources[0]["error"] == "invalid_response"


@pytest.mark.parametrize(
    "update",
    [
        {"timestamp": "invalid"},
        {"record_id": -1},
        {"record_id": True},
        {"data": []},
        {"data": {"user": "x" * 257}},
        {"data": {"user": []}},
    ],
)
def test_bad_event_marks_channel_without_faking_empty_success(monkeypatch, payload, record, update):
    record.update(update)
    payload["records"] = [record]
    _mock_collect(monkeypatch, payload)
    batch = windows.collect_windows(SINCE)
    assert batch.events == []
    assert batch.sources[1]["status"] == "error"
    assert batch.sources[1]["error"] == "invalid_event"


def test_subprocess_uses_static_code_data_environment_timeout_and_no_policy_change(monkeypatch):
    observed = {}

    def run(command, **kwargs):
        observed.update(command=command, **kwargs)
        kwargs["stdout"].write(b'{"sources":[],"records":[]}')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(windows.subprocess, "run", run)
    windows._run_powershell("powershell.exe", SINCE, 5)
    assert observed["timeout"] == 30
    assert observed["env"]["SAURON_SENTINEL_LIMIT"] == "5"
    assert observed["env"]["SAURON_SENTINEL_SINCE"] == "2026-01-01T00:00:00.000000Z"
    assert "-ExecutionPolicy" not in observed["command"]
    script = base64.b64decode(observed["command"][-1]).decode("utf-16-le")
    assert "Get-WinEvent" in script
    assert "Set-ExecutionPolicy" not in script
    assert "auditpol" not in script
    assert "-ComputerName" not in script
    assert ".Message" not in script


def test_subprocess_failure(monkeypatch):
    monkeypatch.setattr(windows.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    with pytest.raises(OSError):
        windows._run_powershell("powershell.exe", SINCE, 5)


def test_subprocess_output_bound(monkeypatch):
    monkeypatch.setattr(windows, "MAX_OUTPUT_BYTES", 5)

    def run(*args, **kwargs):
        kwargs["stdout"].write(b"123456")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(windows.subprocess, "run", run)
    with pytest.raises(ValidationError):
        windows._run_powershell("powershell.exe", SINCE, 5)
