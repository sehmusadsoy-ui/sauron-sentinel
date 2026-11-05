"""Small, versioned preferences with strict types and safe local defaults."""

from __future__ import annotations

from typing import Any

from .models import ValidationError

SEVERITIES = {"low": 0, "medium": 1, "high": 2}


def default_preferences() -> dict:
    return {
        "schema_version": 1,
        "notifications_enabled": False,
        "minimum_severity": "medium",
        "scan_interval_seconds": 15,
    }


def validate_preferences(value: Any) -> dict:
    """Validate the complete schema and return a detached JSON-ready value."""
    if type(value) is not dict or set(value) != set(default_preferences()):
        raise ValidationError("Invalid preferences shape")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValidationError("Invalid preferences schema")
    if type(value["notifications_enabled"]) is not bool:
        raise ValidationError("Invalid notification preference")
    severity = value["minimum_severity"]
    if type(severity) is not str or severity not in SEVERITIES:
        raise ValidationError("Invalid minimum severity")
    interval = value["scan_interval_seconds"]
    if type(interval) is not int or not 5 <= interval <= 3600:
        raise ValidationError("Invalid scan interval")
    return dict(value)
