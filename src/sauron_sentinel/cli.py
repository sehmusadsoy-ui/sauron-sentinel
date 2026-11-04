"""Local command-line collection and replay with auditable JSON artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import nullcontext
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
    args = parser.parse_args(argv)
    try:
        summary = _execute(args)
    except (ValidationError, OSError) as exc:
        print(f"sauron-sentinel: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("sauron-sentinel: interrupted", file=sys.stderr)
        return 130
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0
