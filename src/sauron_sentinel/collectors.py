"""Read bounded JSONL from binary files or stdin, with no device access."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import BinaryIO

from .models import Event, ValidationError, normalize

MAX_LINE_BYTES = 65_536


def _object(pairs: list[tuple]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValidationError("non-finite JSON constant")


def iter_events(stream: BinaryIO, *, max_line_bytes: int = MAX_LINE_BYTES) -> Iterator[Event]:
    """Yield validated observations; abort at the first invalid line.

    The bound includes line endings. Blank lines are ignored. Raw payloads
    are never copied into diagnostic messages.
    """
    if type(max_line_bytes) is not int or not 1 <= max_line_bytes <= MAX_LINE_BYTES:
        raise ValidationError("max_line_bytes must be between 1 and 65536")
    line_number = 0
    while True:
        line = stream.readline(max_line_bytes + 1)
        if not line:
            return
        line_number += 1
        try:
            if len(line) > max_line_bytes:
                raise ValidationError("line exceeds byte limit")
            if not line.strip():
                continue
            text = line.decode("utf-8")
            record = json.loads(text, object_pairs_hook=_object, parse_constant=_reject_constant)
            yield normalize(record)
        except (UnicodeError, ValueError, RecursionError) as exc:
            reason = str(exc) if isinstance(exc, ValidationError) else "invalid UTF-8 or JSON"
            raise ValidationError(f"line {line_number}: {reason}") from exc
