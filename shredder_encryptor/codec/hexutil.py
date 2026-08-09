"""Hexadecimal encoding helpers.

A thin, typed wrapper around :func:`bytes.hex` / :func:`bytes.fromhex`
that normalises the case of the output and converts between
:mod:`codec.text` byte-like inputs without making the caller think
about which variant they hold.
"""

from __future__ import annotations

from typing import Final

from .text import ByteLike

__all__ = [
    "DEFAULT_CASE",
    "to_hex",
    "from_hex",
    "is_hex",
    "hex_to_int",
    "int_to_hex",
    "normalize_hex",
]


#: Default case applied by :func:`to_hex`.  ``"lower"`` matches the
#: convention used by :meth:`bytes.hex` and is what most call sites
#: expect.
DEFAULT_CASE: Final[str] = "lower"

#: ``"lower"`` and ``"upper"`` are the only valid case arguments.
_VALID_CASES: Final[tuple[str, ...]] = ("lower", "upper")


def to_hex(data: ByteLike, case: str = DEFAULT_CASE) -> str:
    """Return the hexadecimal encoding of ``data``.

    ``case`` is normalised to ``"lower"`` or ``"upper"``; any other
    value raises :class:`ValueError`.  Empty input round-trips to an
    empty string.
    """

    if case not in _VALID_CASES:
        raise ValueError(f"case must be one of {_VALID_CASES!r}, got {case!r}")
    encoded: str = bytes(data).hex()
    return encoded if case == "lower" else encoded.upper()


def from_hex(text: str) -> bytes:
    """Decode ``text`` as hexadecimal and return the raw bytes.

    Unlike :func:`bytes.fromhex` the helper also accepts the empty
    string (which decodes to ``b""``) and rejects objects that are
    not ``str`` with a clear error message.
    """

    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    cleaned: str = text.strip()
    if not cleaned:
        return b""
    return bytes.fromhex(cleaned)


def is_hex(text: str) -> bool:
    """Return ``True`` when ``text`` is a valid hexadecimal string."""

    if not isinstance(text, str):
        return False
    candidate: str = text.strip()
    if not candidate:
        return False
    try:
        bytes.fromhex(candidate)
    except ValueError:
        return False
    return True


def hex_to_int(text: str) -> int:
    """Parse ``text`` as a base-16 integer and return it.

    Accepts an optional ``0x`` / ``0X`` prefix and silently strips
    surrounding whitespace so callers can feed it user input without
    extra sanitisation.
    """

    if not isinstance(text, str):
        raise TypeError(f"text must be a str, got {type(text).__name__}")
    cleaned: str = text.strip().lower()
    if cleaned.startswith(("0x", "-0x", "+0x")):
        cleaned = cleaned.replace("0x", "", 1)
    return int(cleaned, 16)


def int_to_hex(
    value: int, case: str = DEFAULT_CASE, prefix: bool = False
) -> str:
    """Return ``value`` formatted as a base-16 string.

    ``prefix`` controls whether a leading ``"0x"`` is included; ``case``
    is validated the same way as :func:`to_hex`.
    """

    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"value must be an int, got {type(value).__name__}")
    if case not in _VALID_CASES:
        raise ValueError(f"case must be one of {_VALID_CASES!r}, got {case!r}")
    text: str = format(abs(value), "x")
    if value < 0:
        text = "-" + text
    if case == "upper":
        text = text.upper()
    return ("0x" + text) if prefix else text


def normalize_hex(text: str, case: str = DEFAULT_CASE) -> str:
    """Re-emit ``text`` in the requested case.

    The function validates that the input is a hexadecimal string; it
    is therefore a safe round-trip helper for code that must accept
    mixed-case input from external sources.
    """

    return to_hex(from_hex(text), case=case)
