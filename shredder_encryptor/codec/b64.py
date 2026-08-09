"""Base64 encoding helpers.

Two flavours are exposed:

* :func:`encode` / :func:`decode` use the standard alphabet.  This is
  the right default for binary data exchanged between Python programs.
* :func:`encode_url` / :func:`decode_url` use the URL-safe alphabet
  (``-`` and ``_`` instead of ``+`` and ``/``) which is what most
  transport layers expect.

The :func:`is_base64` helper validates a string without raising so
callers can branch on malformed input.  All functions return ``str``
for encoded payloads and ``bytes`` for decoded payloads, mirroring
:mod:`codec.text`.
"""

from __future__ import annotations

import base64
import binascii
from typing import Final, Set

from .text import ByteLike, TextLike

__all__ = [
    "encode",
    "decode",
    "encode_url",
    "decode_url",
    "is_base64",
    "b64_to_int",
    "int_to_b64",
]


#: Maximum number of bytes the round-trip helper will accept.  Keeps
#: :func:`b64_to_int` from accidentally allocating a huge integer when
#: the input is malformed or hostile.
_MAX_B64_BYTES: Final[int] = 1 << 20  # 1 MiB of raw data.

#: Supported alphabet identifiers for :func:`is_base64` and
#: :func:`int_to_b64`.
_ALPHABETS: Final[Set[str]] = {"standard", "url"}


def encode(data: ByteLike) -> str:
    """Encode ``data`` with the standard base64 alphabet."""

    return base64.b64encode(bytes(data)).decode("ascii")


def decode(text: TextLike, *, validate: bool = False) -> bytes:
    """Decode a base64 string produced by :func:`encode`.

    When ``validate`` is ``True`` the input is also run through
    :func:`is_base64` and a :class:`ValueError` is raised on
    malformed payloads.  The default of ``False`` mirrors
    :func:`base64.b64decode` with ``validate=False`` which is lenient
    by design.
    """

    if isinstance(text, (bytes, bytearray, memoryview)):
        text = bytes(text).decode("ascii")
    if not isinstance(text, str):
        raise TypeError(
            f"text must be str or bytes-like, got {type(text).__name__}"
        )
    if validate and not is_base64(text, alphabet="standard"):
        raise ValueError("text is not valid base64")
    return base64.b64decode(text, validate=validate)


def encode_url(data: ByteLike) -> str:
    """Encode ``data`` with the URL-safe base64 alphabet."""

    return base64.urlsafe_b64encode(bytes(data)).decode("ascii")


def decode_url(text: TextLike, *, validate: bool = False) -> bytes:
    """Decode a URL-safe base64 string produced by :func:`encode_url`."""

    if isinstance(text, (bytes, bytearray, memoryview)):
        text = bytes(text).decode("ascii")
    if not isinstance(text, str):
        raise TypeError(
            f"text must be str or bytes-like, got {type(text).__name__}"
        )
    if validate and not is_base64(text, alphabet="url"):
        raise ValueError("text is not valid base64")
    return base64.urlsafe_b64decode(text)


def is_base64(text: str, *, alphabet: str = "standard") -> bool:
    """Return ``True`` when ``text`` is a valid base64 string.

    ``alphabet`` selects the expected character set; the default
    ``"standard"`` is the plus/slash variant, ``"url"`` accepts
    dash/underscore instead.  The check tolerates missing padding so
    short payloads that omit the trailing ``=`` characters are
    accepted.
    """

    if not isinstance(text, str):
        return False
    candidate: str = text.strip()
    if not candidate:
        return False
    if alphabet == "standard":
        allowed: Set[str] = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )
    elif alphabet == "url":
        allowed = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
        )
    else:
        raise ValueError(
            f"alphabet must be 'standard' or 'url', got {alphabet!r}"
        )
    if any(ch not in allowed for ch in candidate):
        return False
    # ``len % 4`` must be 0, 2 or 3; 1 is never valid base64.  Padding
    # characters may only appear at the very end of the string.
    remainder: int = len(candidate) % 4
    if remainder == 1:
        return False
    if "=" in candidate and not candidate.endswith(
        "=" * (4 - remainder or 4)
    ):
        return False
    try:
        if alphabet == "standard":
            base64.b64decode(candidate, validate=True)
        else:
            base64.urlsafe_b64decode(candidate)
    except (binascii.Error, ValueError):
        return False
    return True


def b64_to_int(text: str, *, alphabet: str = "standard") -> int:
    """Decode ``text`` as base64 and interpret the result as a big integer."""

    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    if alphabet == "standard":
        raw: bytes = decode(text, validate=True)
    elif alphabet == "url":
        raw = decode_url(text, validate=True)
    else:
        raise ValueError(
            f"alphabet must be 'standard' or 'url', got {alphabet!r}"
        )
    if len(raw) > _MAX_B64_BYTES:
        raise ValueError("input is too large to be converted to an int")
    return int.from_bytes(raw, "big", signed=False)


def int_to_b64(
    value: int, *, alphabet: str = "standard", min_length: int = 0
) -> str:
    """Encode ``value`` as a base64 string.

    ``min_length`` lets callers left-pad the output with zero bytes,
    which is useful when a value must occupy a fixed-width slot (for
    example, an RSA modulus).
    """

    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"value must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError("value must be non-negative")
    if min_length < 0:
        raise ValueError("min_length must be non-negative")
    if alphabet not in _ALPHABETS:
        raise ValueError(
            f"alphabet must be 'standard' or 'url', got {alphabet!r}"
        )
    raw: bytes = value.to_bytes(
        max(min_length, (value.bit_length() + 7) // 8 or 1), "big"
    )
    return (encode if alphabet == "standard" else encode_url)(raw)
