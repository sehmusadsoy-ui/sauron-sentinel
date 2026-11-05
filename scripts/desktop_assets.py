"""Generate the original Sentinel eye icon with only the Python standard library."""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _pixel(x: float, y: float) -> tuple[int, int, int, int]:
    """Evaluate a simple rounded-square and eye mark in normalized coordinates."""
    qx, qy = abs(x - 0.5) - 0.27, abs(y - 0.5) - 0.27
    distance = math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - 0.19
    if distance > 0:
        return (0, 0, 0, 0)
    color = (17, 36, 43, 255) if distance < -0.018 else (53, 105, 98, 255)
    eye_x = abs(x - 0.5) / 0.31
    if eye_x <= 1:
        edge = 0.185 * (1 - eye_x**1.6)
        if abs(abs(y - 0.5) - edge) < 0.018:
            color = (82, 213, 180, 255)
    radius = math.hypot(x - 0.5, y - 0.5)
    if radius < 0.087:
        color = (82, 213, 180, 255)
    if radius < 0.031:
        color = (17, 36, 43, 255)
    return color


def _png(size: int) -> bytes:
    rows = bytearray()
    # Four samples per pixel keep the vector edges smooth at small icon sizes.
    for y in range(size):
        rows.append(0)
        for x in range(size):
            samples = [
                _pixel((x + dx) / size, (y + dy) / size)
                for dx, dy in ((0.25, 0.25), (0.75, 0.25), (0.25, 0.75), (0.75, 0.75))
            ]
            rows.extend(sum(sample[channel] for sample in samples) // 4 for channel in range(4))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(bytes(rows), level=9))
        + _chunk(b"IEND", b"")
    )


def icon_bytes(sizes: tuple[int, ...] = (16, 32, 48, 64, 128, 256)) -> bytes:
    """Return a multi-resolution Windows ICO containing original PNG artwork."""
    if (
        not sizes
        or len(set(sizes)) != len(sizes)
        or any(type(size) is not int or not 1 <= size <= 256 for size in sizes)
    ):
        raise ValueError("Icon sizes must be unique integers in 1..256")
    images = [_png(size) for size in sizes]
    offset = 6 + 16 * len(images)
    entries = []
    for size, payload in zip(sizes, images, strict=True):
        entries.append(
            struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(payload), offset)
        )
        offset += len(payload)
    return struct.pack("<HHH", 0, 1, len(images)) + b"".join(entries) + b"".join(images)


def write_icon(path: Path) -> None:
    """Create the repository icon; callers choose the explicit destination."""
    path.write_bytes(icon_bytes())
