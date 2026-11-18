"""Opt-in, read-only local Windows security posture checks.

This snapshot is advisory, not an intrusion detector or a clean-bill-of-health.
Results are returned only to the requesting loopback dashboard connection.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import subprocess
import tempfile
from importlib import resources
from typing import Any

from .windows import _powershell

MAX_OUTPUT_BYTES = 32_768
MAX_CHECKS = 32
VALID_STATUSES = frozenset({"OK", "REVIEW", "UNKNOWN"})


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "error": reason, "checks": []}


def _parse_output(payload: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Invalid audit output") from exc
    if type(decoded) is not list or not 1 <= len(decoded) <= MAX_CHECKS:
        raise ValueError("Invalid audit check count")

    checks = []
    for item in decoded:
        if type(item) is not dict or set(item) != {"Check", "Status", "Detail"}:
            raise ValueError("Invalid audit check schema")
        name, status, detail = item["Check"], item["Status"], item["Detail"]
        if (
            type(name) is not str
            or type(status) is not str
            or type(detail) is not str
            or not 1 <= len(name) <= 100
            or status not in VALID_STATUSES
            or len(detail) > 500
        ):
            raise ValueError("Invalid audit check field")
        checks.append({"name": name, "status": status, "detail": detail})
    return {
        "status": "completed",
        "checks": checks,
        "review_count": sum(c["status"] == "REVIEW" for c in checks),
        "unknown_count": sum(c["status"] == "UNKNOWN" for c in checks),
    }


def _collect(executable: str) -> bytes:
    script = (
        resources.files("sauron_sentinel")
        .joinpath("windows_exposure.ps1")
        .read_text(encoding="utf-8")
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    env = os.environ.copy()
    env["SAURON_EXPOSURE_JSON"] = "1"
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            stdout=output,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=env,
            timeout=20,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            raise OSError("Exposure check failed")
        output.seek(0)
        data = output.read(MAX_OUTPUT_BYTES + 1)
    if len(data) > MAX_OUTPUT_BYTES:
        raise ValueError("Exposure output too large")
    return data


def run_exposure_audit() -> dict[str, Any]:
    """Read Windows settings on explicit request; never modify or persist them."""
    if platform.system() != "Windows":
        return _unavailable("not_windows")
    executable = _powershell()
    if not executable:
        return _unavailable("powershell_unavailable")
    try:
        return _parse_output(_collect(executable))
    except subprocess.TimeoutExpired:
        return _unavailable("timeout")
    except (OSError, ValueError):
        return _unavailable("audit_failed")
