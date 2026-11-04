"""Exercise installed-style commands and durable failure artifacts end to end."""

import io
import json
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace

import pytest

from sauron_sentinel.cli import main


def command(tmp_path, *arguments, stdin=None):
    stdout, stderr = io.StringIO(), io.StringIO()
    stream = io.TextIOWrapper(io.BytesIO((stdin or "").encode("utf-8")))
    with pytest.MonkeyPatch.context() as patch, redirect_stdout(stdout), redirect_stderr(stderr):
        patch.chdir(tmp_path)
        patch.setattr(sys, "stdin", stream)
        try:
            status = main(list(map(str, arguments)))
        except SystemExit as exc:
            status = exc.code
    return SimpleNamespace(returncode=status, stdout=stdout.getvalue(), stderr=stderr.getvalue())


def write_records(path, *records):
    path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")


def test_demo_is_reproducible_and_explicitly_synthetic(tmp_path):
    outputs = [tmp_path / "one", tmp_path / "two"]
    for output in outputs:
        result = command(tmp_path, "demo", "--output", output)
        assert result.returncode == 0, result.stderr
        summary = json.loads(result.stdout)
        assert summary["schema_version"] == 1
        assert summary["version"] == "0.2.0"
        assert summary["status"] == "complete"
        assert summary["events_processed"] > 0
        assert summary["synthetic_events"] == summary["events_processed"]
        assert summary["alerts_emitted"] == 3
        alerts = [json.loads(line) for line in (output / "alerts.jsonl").read_text().splitlines()]
        assert {alert["rule_id"] for alert in alerts} == {
            "auth-failure-burst",
            "rf-activity-burst",
            "motion-without-maintenance",
        }
        assert all(alert["synthetic"] for alert in alerts)
        events = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
        event_ids = {event["event_id"] for event in events}
        assert all(set(alert["event_ids"]) <= event_ids for alert in alerts)
        assert json.loads((output / "summary.json").read_text()) == summary
    for filename in ("events.jsonl", "alerts.jsonl", "summary.json"):
        assert (outputs[0] / filename).read_bytes() == (outputs[1] / filename).read_bytes()


def test_run_accepts_stdin_and_normalizes_records(tmp_path, record):
    output = tmp_path / "run"
    data = json.dumps(record(timestamp="2026-01-01T03:00:00+03:00")) + "\n"
    result = command(tmp_path, "run", "--input", "-", "--output", output, stdin=data)
    assert result.returncode == 0, result.stderr
    event = json.loads((output / "events.jsonl").read_text())
    assert event["timestamp"].startswith("2026-01-01T00:00:00")
    assert event["event_id"]
    assert json.loads(result.stdout)["events_processed"] == 1


def test_validate_checks_schema_without_creating_outputs(tmp_path, record):
    source = tmp_path / "records.jsonl"
    write_records(source, record(10), record(0))
    result = command(tmp_path, "validate", "--input", source)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "sentinel-output").exists()


def test_run_preserves_existing_directory(tmp_path, record):
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("do not overwrite", encoding="utf-8")
    source = tmp_path / "records.jsonl"
    write_records(source, record())
    result = command(tmp_path, "run", "--input", source, "--output", output)
    assert result.returncode == 2
    assert marker.read_text() == "do not overwrite"
    assert sorted(p.name for p in output.iterdir()) == ["keep.txt"]


def test_invalid_rule_does_not_create_output(tmp_path, record):
    source, rules, output = tmp_path / "records.jsonl", tmp_path / "bad.toml", tmp_path / "new"
    write_records(source, record())
    rules.write_text("schema_version = 999\n", encoding="utf-8")
    result = command(tmp_path, "run", "--input", source, "--rules", rules, "--output", output)
    assert result.returncode == 2
    assert not output.exists()


def test_bad_record_leaves_explicit_partial_result(tmp_path, record):
    source, output = tmp_path / "records.jsonl", tmp_path / "partial"
    source.write_text(json.dumps(record()) + "\ninvalid\n", encoding="utf-8")
    result = command(tmp_path, "run", "--input", source, "--output", output)
    assert result.returncode == 2
    assert result.stderr
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == "failed"
    assert summary["events_processed"] == 1
    assert summary["error"]
    assert len((output / "events.jsonl").read_text().splitlines()) == 1


def test_event_limit_rejects_excess_instead_of_silent_truncation(tmp_path, record):
    source, output = tmp_path / "records.jsonl", tmp_path / "limited"
    write_records(source, record(), record(1))
    result = command(tmp_path, "run", "--input", source, "--output", output, "--max-events", 1)
    assert result.returncode == 2
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == "failed"
    assert summary["events_processed"] == 1


def test_run_rejects_event_time_regression(tmp_path, record):
    source, output = tmp_path / "records.jsonl", tmp_path / "order"
    write_records(source, record(10), record(0))
    result = command(tmp_path, "run", "--input", source, "--output", output)
    assert result.returncode == 2
    assert json.loads((output / "summary.json").read_text())["status"] == "failed"


@pytest.mark.parametrize("limit", ["0", "-1", "invalid"])
def test_invalid_limits_are_argument_errors(tmp_path, limit):
    result = command(tmp_path, "validate", "--input", "-", "--max-events", limit, stdin="")
    assert result.returncode == 2


def test_help_and_version_are_available(tmp_path):
    assert command(tmp_path, "--help").returncode == 0
    result = command(tmp_path, "--version")
    assert result.returncode == 0
    assert "0.2.0" in result.stdout


def test_module_entrypoint_smoke(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "sauron_sentinel", "--version"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0.2.0"


def test_excessive_toml_nesting_produces_no_cli_traceback(tmp_path):
    rules, output = tmp_path / "deep.toml", tmp_path / "unused"
    rules.write_text("schema_version=1\nrules=" + "[" * 600 + "1" + "]" * 600, encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sauron_sentinel",
            "run",
            "--input",
            "missing.jsonl",
            "--rules",
            str(rules),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=20,
        check=False,
    )
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("available", [True, False])
def test_collect_windows_exports_real_records_and_status(tmp_path, record, monkeypatch, available):
    from sauron_sentinel import windows
    from sauron_sentinel.models import normalize

    event = normalize(record(synthetic=False))
    status = "ok" if available else "unavailable"
    monkeypatch.setattr(
        windows,
        "collect_windows",
        lambda *_a, **_k: SimpleNamespace(
            events=[event] if available else [],
            sources=[{"channel": "System", "status": status, "event_count": int(available)}],
        ),
    )
    output = tmp_path / "windows"
    result = command(tmp_path, "collect-windows", "--output", output)
    assert result.returncode == (0 if available else 3)
    summary = json.loads(result.stdout)
    assert summary["synthetic_events"] == 0
    assert summary["sources"][0]["status"] == status
    assert (output / "events.jsonl").exists()


@pytest.mark.parametrize("flag,value", [("--limit", 0), ("--limit", 1001), ("--since-hours", 169)])
def test_collect_windows_rejects_invalid_limits(tmp_path, flag, value):
    result = command(tmp_path, "collect-windows", flag, value)
    assert result.returncode == 2
    assert not (tmp_path / "windows-output").exists()


def test_serve_command_passes_settings_and_handles_stop(tmp_path, monkeypatch):
    from sauron_sentinel import live

    captured = []
    monkeypatch.setattr(live, "serve", lambda *args: captured.append(args))
    result = command(tmp_path, "serve", "--port", 8888, "--interval", 30, "--open-browser")
    assert result.returncode == 0
    assert captured[0][1:] == (8888, 30, 24, True)

    def interrupt(*_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(live, "serve", interrupt)
    assert command(tmp_path, "serve").returncode == 130
