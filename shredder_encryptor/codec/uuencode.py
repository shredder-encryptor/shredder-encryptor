"""UUencode / UUdecode helpers.

These functions wrap :mod:`binascii` to provide a friendlier surface
than the low-level ``b2a_uu`` / ``a2b_uu`` routines.

The classic ``begin`` / ``end`` markers are not produced or consumed
automatically -- callers that need them must wrap the encoded body
themselves.
"""

from __future__ import annotations

import binascii

from .text import ByteLike

__all__ = ["uuencode", "uudecode"]


def uuencode(data: ByteLike, *, backtick: bool = False) -> bytes:
    """Return ``data`` encoded as uuencoded bytes.

    ``backtick`` switches the encoder from the historic 32-character
    range (`` `` through ``_``) to the modern 64-character range
    (``!`` through ``_``) used by some mail gateways.
    """

    payload: bytes = bytes(data)
    return binascii.b2a_uu(payload, backtick=backtick)


def uudecode(data: ByteLike) -> bytes:
    """Decode ``data`` produced by :func:`uuencode`."""

    payload: bytes = bytes(data)
    return binascii.a2b_uu(payload)