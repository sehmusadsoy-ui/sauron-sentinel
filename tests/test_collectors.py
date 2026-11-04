"""The JSONL collector rejects ambiguous and unbounded input."""

import io
import json

import pytest

from sauron_sentinel.collectors import iter_events
from sauron_sentinel.models import ValidationError


def test_reads_binary_jsonl_and_skips_blank_lines(record):
    stream = io.BytesIO(("\n" + json.dumps(record()) + "\n\n").encode())
    events = list(iter_events(stream))
    assert len(events) == 1
    assert events[0].kind == "auth.failure"


def test_empty_stream():
    assert list(iter_events(io.BytesIO(b""))) == []


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json\n",
        b"[]\n",
        b'{"source":"a","source":"b"}\n',
        b'{"attributes":{"score":1,"score":2}}\n',
        b'{"attributes":{"score":NaN}}\n',
        b'{"attributes":{"score":Infinity}}\n',
        b"\xff\n",
        b" " * (64 * 1024 + 1) + b"\n",
    ],
)
def test_invalid_input_reports_line_number(payload):
    with pytest.raises(ValidationError, match="(?i)line 2"):
        list(iter_events(io.BytesIO(b"\n" + payload)))


def test_failure_after_valid_record_is_not_silently_skipped(record):
    stream = io.BytesIO((json.dumps(record()) + "\ninvalid\n").encode())
    iterator = iter_events(stream)
    assert next(iterator).device_id == "host-01"
    with pytest.raises(ValidationError, match="(?i)line 2"):
        next(iterator)
