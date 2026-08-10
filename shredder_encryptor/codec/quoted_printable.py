"""Quoted-printable encoding (RFC 2045).

The format escapes bytes that are not safe for transmission over
7-bit channels.  It is most commonly seen in e-mail bodies.
"""

from __future__ import annotations

import binascii
from typing import Final

from .text import ByteLike

__all__ = ["encode_qp", "decode_qp", "HEADER_LINE_LENGTH"]


#: Default line length used by :func:`encode_qp`.  Matches the RFC
#: recommendation for body parts.
HEADER_LINE_LENGTH: Final[int] = 76


def encode_qp(
    data: ByteLike,
    *,
    header: bool = False,
    max_line_length: int = HEADER_LINE_LENGTH,
) -> bytes:
    """Return ``data`` encoded with quoted-printable."""

    payload: bytes = bytes(data) if not isinstance(
        data, (bytes, bytearray, memoryview)
    ) else bytes(data)
    if not isinstance(payload, bytes):  # pragma: no cover - defensive
        raise TypeError(
            f"data must be bytes-like, got {type(payload).__name__}"
        )
    if not isinstance(max_line_length, int) or max_line_length <= 0:
        raise ValueError("max_line_length must be a positive int")
    # ``b2a_qp`` accepts ``header`` and ``maxlinelen`` since Python 3.10.
    return binascii.b2a_qp(payload, header=header, maxlinelen=max_line_length)


def decode_qp(data: ByteLike, *, header: bool = False) -> bytes:
    """Decode ``data`` from quoted-printable to raw bytes."""

    payload: bytes = bytes(data) if not isinstance(
        data, (bytes, bytearray, memoryview)
    ) else bytes(data)
    return binascii.a2b_qp(payload, header=header)