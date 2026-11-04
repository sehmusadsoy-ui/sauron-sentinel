"""Read-only collection of selected local Windows Event Log observations.

No administrator prompt, audit-policy changes, remote queries, or security-setting
changes are made. Permission failures remain visible in per-channel availability.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from .models import Event, ValidationError, format_timestamp, normalize

CHANNELS = ("System", "Security", "Microsoft-Windows-Windows Defender/Operational")
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
_PROVIDERS = {
    "scm": "service control manager",
    "security": "microsoft-windows-security-auditing",
    "eventlog": "microsoft-windows-eventlog",
    "classic": "eventlog",
    "kernel": "microsoft-windows-kernel-power",
    "defender": "microsoft-windows-windows defender",
}
_EVENT_TYPES = {
    ("System", 7045): ("scm", "service.installed"),
    ("System", 7040): ("scm", "service.start_changed"),
    ("System", 104): ("eventlog", "log.cleared"),
    ("System", 6005): ("classic", "system.started"),
    ("System", 6006): ("classic", "system.stopped"),
    ("System", 6008): ("classic", "system.unexpected_shutdown"),
    ("System", 41): ("kernel", "system.unexpected_shutdown"),
    ("Security", 4625): ("security", "auth.failure"),
    ("Security", 4624): ("security", "auth.success"),
    ("Security", 4720): ("security", "account.created"),
    ("Security", 4732): ("security", "group.member_added"),
    ("Security", 1102): ("eventlog", "log.cleared"),
    (CHANNELS[2], 1116): ("defender", "defender.threat"),
    (CHANNELS[2], 1117): ("defender", "defender.action"),
    (CHANNELS[2], 5001): ("defender", "defender.disabled"),
    (CHANNELS[2], 5007): ("defender", "defender.config_changed"),
}
_SAFE_FIELDS = {
    "user",
    "target_user",
    "logon_type",
    "group_name",
    "service_name",
    "service_type",
    "start_type",
    "old_start_type",
    "threat_name",
}
_ERROR_CODES = {
    "permission_denied",
    "channel_unavailable",
    "channel_disabled",
    "collection_failed",
    "invalid_event",
}


@dataclass(frozen=True, slots=True)
class CollectionBatch:
    events: list[Event]
    sources: list[dict[str, Any]]


def _unavailable(error: str, status: str = "unavailable") -> CollectionBatch:
    return CollectionBatch(
        [],
        [
            {"channel": channel, "status": status, "event_count": 0, "error": error}
            for channel in CHANNELS
        ],
    )


def _powershell() -> str | None:
    system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    executable = system / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if executable.is_file():
        return str(executable)
    return shutil.which("powershell.exe") or shutil.which("pwsh.exe")


def _run_powershell(executable: str, since: datetime, limit: int) -> bytes:
    script = (
        resources.files("sauron_sentinel")
        .joinpath("windows_collector.ps1")
        .read_text(encoding="utf-8")
    )
    # Static source is supplied as a command, without changing execution policy.
    # User input remains data in this child process's environment, never code.
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    environment = os.environ.copy()
    environment["SAURON_SENTINEL_SINCE"] = format_timestamp(since)
    environment["SAURON_SENTINEL_LIMIT"] = str(limit)
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            stdout=output,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=environment,
            timeout=30,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode:
            raise OSError("PowerShell collection failed")
        output.seek(0)
        payload = output.read(MAX_OUTPUT_BYTES + 1)
    if len(payload) > MAX_OUTPUT_BYTES:
        raise ValidationError("Collector output exceeds limit")
    return payload


def _record_event(record: Any, device_id: str) -> Event | None:
    if not isinstance(record, dict):
        raise ValidationError("Invalid event record")
    channel, event_id = record.get("channel"), record.get("event_id")
    if not isinstance(channel, str) or type(event_id) is not int:
        raise ValidationError("Invalid event identity")
    definition = _EVENT_TYPES.get((channel, event_id))
    if definition is None:
        return None
    provider = record.get("provider")
    if not isinstance(provider, str) or provider.lower() != _PROVIDERS[definition[0]]:
        return None
    record_id = record.get("record_id")
    if type(record_id) is not int or not 0 <= record_id <= 2**53 - 1:
        raise ValidationError("Invalid record identity")
    data = record.get("data")
    if not isinstance(data, dict):
        raise ValidationError("Invalid event fields")
    attributes: dict[str, Any] = {
        "provider": provider,
        "event_id": event_id,
        "record_id": record_id,
        "channel": channel,
    }
    for key in _SAFE_FIELDS:
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or len(value) > 256:
            raise ValidationError("Invalid selected event field")
        if key == "logon_type":
            if value.isascii() and value.isdigit() and 0 <= int(value) <= 99:
                attributes[key] = int(value)
        else:
            attributes[key] = value
    if record.get("fields_truncated") is True:
        attributes["fields_truncated"] = True
    return normalize(
        {
            "schema_version": 1,
            "timestamp": record.get("timestamp"),
            "source": "windows-eventlog",
            "kind": definition[1],
            "device_id": device_id,
            "synthetic": False,
            "attributes": attributes,
        }
    )


def _parse_batch(payload: bytes, limit: int) -> CollectionBatch:
    data = json.loads(payload.decode("utf-8-sig"))
    if not isinstance(data, dict) or set(data) != {"sources", "records"}:
        raise ValidationError("Invalid collector response")
    sources, records = data["sources"], data["records"]
    if not isinstance(sources, list) or len(sources) != len(CHANNELS):
        raise ValidationError("Invalid source response")
    statuses = {}
    for source in sources:
        if not isinstance(source, dict):
            raise ValidationError("Invalid source response")
        channel, status = source.get("channel"), source.get("status")
        if (
            channel not in CHANNELS
            or channel in statuses
            or status
            not in (
                "ok",
                "unavailable",
                "error",
            )
        ):
            raise ValidationError("Invalid source status")
        statuses[channel] = {
            "channel": channel,
            "status": status,
            "event_count": 0,
            "limit_reached": source.get("limit_reached") is True,
        }
        if status != "ok":
            error = source.get("error")
            statuses[channel]["error"] = error if error in _ERROR_CODES else "collection_failed"
    if not isinstance(records, list) or len(records) > len(CHANNELS) * limit:
        raise ValidationError("Invalid record count")
    device_id = (
        "windows-" + hashlib.sha256(socket.gethostname().lower().encode("utf-8")).hexdigest()[:16]
    )
    events = []
    seen = set()
    channel_records = {channel: 0 for channel in CHANNELS}
    for record in records:
        channel = record.get("channel") if isinstance(record, dict) else None
        if not isinstance(channel, str) or channel not in statuses:
            raise ValidationError("Invalid record channel")
        channel_records[channel] += 1
        if channel_records[channel] > limit:
            raise ValidationError("Invalid channel record count")
        try:
            event = _record_event(record, device_id)
        except ValidationError:
            statuses[channel].update(status="error", error="invalid_event")
            continue
        if event is not None and event.event_id not in seen:
            seen.add(event.event_id)
            events.append(event)
            statuses[channel]["event_count"] += 1
    events.sort(key=lambda event: (event.timestamp, event.event_id))
    return CollectionBatch(events, [statuses[channel] for channel in CHANNELS])


def collect_windows(since: datetime, limit: int = 200) -> CollectionBatch:
    """Collect up to ``limit`` newest matching events from each selected channel.

    ``limit_reached`` flags possible truncation, rather than promising complete
    coverage. Existing audit configuration and current-user permissions apply.
    Values selected for display are capped at 256 characters. IDs remain stable
    on recollection because the original Windows record ID is retained.
    """
    if not isinstance(since, datetime) or since.tzinfo is None or since.utcoffset() is None:
        raise ValidationError("since must be an offset-aware datetime")
    try:
        since = since.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ValidationError("since cannot be represented in UTC") from exc
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValidationError("limit must be an integer in 1..1000 per channel")
    if platform.system() != "Windows":
        return _unavailable("not_windows")
    executable = _powershell()
    if executable is None:
        return _unavailable("powershell_unavailable")
    try:
        payload = _run_powershell(executable, since, limit)
        return _parse_batch(payload, limit)
    except subprocess.TimeoutExpired:
        return _unavailable("timeout", "error")
    except OSError:
        return _unavailable("collection_failed", "error")
    except (UnicodeError, ValueError, RecursionError, TypeError):
        return _unavailable("invalid_response", "error")
