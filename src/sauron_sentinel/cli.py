"""Local command-line collection and replay with auditable JSON artifacts."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from importlib import resources
from pathlib import Path
from typing import TextIO

from . import __version__
from .collectors import iter_events
from .engine import RuleEngine
from .models import ValidationError
from .rules import load_rules


def _write_json(stream: TextIO, value: dict) -> None:
    stream.write(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n")


def _positive_limit(value: str) -> int:
    try:
        count = int(value)
        if not 1 <= count <= 1_000_000:
            raise ValueError
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be between 1 and 1000000") from exc
    return count


def _summary() -> dict:
    return {
        "schema_version": 1,
        "version": __version__,
        "status": "failed",
        "events_processed": 0,
        "synthetic_events": 0,
        "alerts_emitted": 0,
    }


def _input(path: str):
    return nullcontext(sys.stdin.buffer) if path == "-" else Path(path).open("rb")


def _execute(args: argparse.Namespace) -> dict:
    summary = _summary()
    if args.command == "validate":
        with _input(args.input) as stream:
            for event in iter_events(stream):
                if summary["events_processed"] >= args.max_events:
                    raise ValidationError("input exceeds --max-events; no silent truncation")
                summary["events_processed"] += 1
                summary["synthetic_events"] += int(event.synthetic)
        summary["status"] = "complete"
        return summary

    engine = RuleEngine(load_rules(args.rules))
    output = Path(args.output)
    # Exclusive creation protects previous runs and user files, including symlinks.
    output.mkdir(parents=True, exist_ok=False)
    try:
        input_context = (
            resources.files("sauron_sentinel").joinpath("demo.jsonl").open("rb")
            if args.command == "demo"
            else _input(args.input)
        )
        with (
            input_context as stream,
            (output / "events.jsonl").open("x", encoding="utf-8", newline="\n") as events,
            (output / "alerts.jsonl").open("x", encoding="utf-8", newline="\n") as alerts,
        ):
            for event in iter_events(stream):
                if summary["events_processed"] >= args.max_events:
                    raise ValidationError("input exceeds --max-events; no silent truncation")
                detections = engine.process(event)
                _write_json(events, event.to_dict())
                summary["events_processed"] += 1
                summary["synthetic_events"] += int(event.synthetic)
                for alert in detections:
                    _write_json(alerts, alert.to_dict())
                    summary["alerts_emitted"] += 1
        summary["status"] = "complete"
    except (ValidationError, OSError) as exc:
        summary["error"] = str(exc)
        raise
    finally:
        with (output / "summary.json").open("x", encoding="utf-8", newline="\n") as report:
            _write_json(report, summary)
    return summary


def _collect_windows(args: argparse.Namespace) -> dict:
    from .windows import collect_windows

    if not 1 <= args.since_hours <= 168 or not 1 <= args.limit <= 1000:
        raise ValidationError("since-hours must be 1..168 and limit 1..1000")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    batch = collect_windows(datetime.now(UTC) - timedelta(hours=args.since_hours), limit=args.limit)
    with (output / "events.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
        for event in batch.events:
            _write_json(stream, event.to_dict())
    available = any(source["status"] == "ok" for source in batch.sources)
    summary = {
        "schema_version": 1,
        "version": __version__,
        "status": "complete" if available else "unavailable",
        "events_processed": len(batch.events),
        "synthetic_events": 0,
        "sources": batch.sources,
    }
    with (output / "summary.json").open("x", encoding="utf-8", newline="\n") as stream:
        _write_json(stream, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sauron-sentinel",
        description="Analyze local telemetry with deterministic, explainable rules.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, description in (
        ("run", "Collect and analyze local JSONL telemetry"),
        ("demo", "Replay bundled synthetic observations (no hardware required)"),
        ("validate", "Check event schema and input limits without writing files"),
    ):
        command = commands.add_parser(name, help=description)
        if name != "demo":
            command.add_argument("--input", required=True, help="JSONL path, or - for stdin")
        if name != "validate":
            command.add_argument("--output", default="sentinel-output", help="New output directory")
            command.add_argument("--rules", type=Path, help="Custom v1 TOML rule file")
        command.add_argument("--max-events", type=_positive_limit, default=100_000)
    live = commands.add_parser("serve", help="Open a local dashboard with real Windows logs")
    live.add_argument("--data-dir", type=Path, default=Path("sentinel-data"))
    live.add_argument("--port", type=int, default=8765)
    live.add_argument(
        "--interval", type=int, help="Scan interval in seconds (saved setting, or 15 by default)"
    )
    live.add_argument("--lookback-hours", type=int, default=24)
    live.add_argument("--open-browser", action="store_true")
    windows = commands.add_parser("collect-windows", help="Export selected local Windows events")
    windows.add_argument("--output", default="windows-output")
    windows.add_argument("--since-hours", type=int, default=24)
    windows.add_argument("--limit", type=int, default=200)
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            from .live import serve

            serve(args.data_dir, args.port, args.interval, args.lookback_hours, args.open_browser)
            return 0
        summary = _collect_windows(args) if args.command == "collect-windows" else _execute(args)
    except sqlite3.Error:
        print(
            "sauron-sentinel: cannot access the local database; existing data was preserved",
            file=sys.stderr,
        )
        return 2
    except (ValidationError, OSError) as exc:
        print(f"sauron-sentinel: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("sauron-sentinel: interrupted", file=sys.stderr)
        return 130
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 3 if summary["status"] == "unavailable" else 0
