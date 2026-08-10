"""Random tokens and constant-time comparison helpers.

The functions are thin, typed wrappers around :mod:`secrets` and
:mod:`hmac`.  They exist so callers can ``import`` everything from one
place and document the security expectations in a single location.
"""

from __future__ import annotations

import hmac
import secrets
import string
from collections.abc import Sequence
from typing import Final

from .text import ByteLike

__all__ = [
    "DEFAULT_TOKEN_LENGTH",
    "DEFAULT_ALPHABET",
    "token_bytes",
    "token_hex",
    "token_urlsafe",
    "new_token",
    "constant_time_eq",
]


#: Default byte length for cryptographically secure tokens.  32 bytes
#: (256 bits) matches common recommendations for session identifiers.
DEFAULT_TOKEN_LENGTH: Final[int] = 32

#: Default alphabet used by :func:`new_token`.  Letters and digits are
#: safe for URLs, file names and most human-facing contexts.
DEFAULT_ALPHABET: Final[str] = string.ascii_letters + string.digits


def token_bytes(length: int = DEFAULT_TOKEN_LENGTH) -> bytes:
    """Return ``length`` cryptographically secure random bytes."""

    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError(f"length must be an int, got {type(length).__name__}")
    if length < 0:
        raise ValueError("length must be non-negative")
    return secrets.token_bytes(length)


def token_hex(length: int = DEFAULT_TOKEN_LENGTH) -> str:
    """Return ``length`` random bytes as a lower-case hex string."""

    return secrets.token_hex(length)


def token_urlsafe(length: int = DEFAULT_TOKEN_LENGTH) -> str:
    """Return ``length`` random bytes encoded as URL-safe base64."""

    return secrets.token_urlsafe(length)


def new_token(
    length: int = DEFAULT_TOKEN_LENGTH,
    *,
    alphabet: Sequence[str] | str = DEFAULT_ALPHABET,
) -> str:
    """Return a cryptographically secure token drawn from ``alphabet``.

    ``alphabet`` may be any sequence of single-character strings; the
    function rejects entries that contain duplicates or empty values
    so the resulting token cannot leak entropy by accident.
    """

    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError(f"length must be an int, got {type(length).__name__}")
    if length < 0:
        raise ValueError("length must be non-negative")
    chars: list[str] = list(alphabet)
    if not chars:
        raise ValueError("alphabet must not be empty")
    if any(not isinstance(ch, str) or len(ch) != 1 for ch in chars):
        raise TypeError("alphabet entries must be single-character strings")
    if len(set(chars)) != len(chars):
        raise ValueError("alphabet must not contain duplicate characters")
    return "".join(secrets.choice(chars) for _ in range(length))


def constant_time_eq(a: ByteLike | str, b: ByteLike | str) -> bool:
    """Return ``True`` when ``a`` and ``b`` are byte-for-byte equal.

    The comparison runs in time proportional to the length of the
    shorter input, mirroring :func:`hmac.compare_digest`.  Strings are
    accepted as a convenience and are encoded with UTF-8 first so the
    caller never has to remember which form is expected.
    """

    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(bytes(a), bytes(b))