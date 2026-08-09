"""Text encoding helpers used across the cipher implementations.

The functions in this module wrap the standard library with a small,
consistent error model so the rest of the project can rely on them
without having to remember which exceptions each codec raises.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator
from typing import Final, List, Tuple, Union

__all__ = [
    "DEFAULT_ENCODING",
    "ENCODING_ERRORS",
    "to_bytes",
    "from_bytes",
    "normalize",
    "safe_str",
    "chunk",
    "codepoint_distribution",
]


#: Default encoding used when callers do not specify one.  UTF-8 is the
#: only universally supported encoding on every platform the project
#: targets, so picking it as the default keeps the call sites simple.
DEFAULT_ENCODING: Final[str] = "utf-8"

#: Default error policy applied by :func:`to_bytes` and
#: :func:`from_bytes`.  ``"strict"`` raises on the first invalid byte
#: so silent corruption cannot happen.
ENCODING_ERRORS: Final[str] = "strict"

#: Aliases accepted by :func:`normalize` so callers do not have to
#: remember the exact NFxx spelling.
NORMALIZATION_FORMS: Final[Tuple[str, ...]] = ("NFC", "NFD", "NFKC", "NFKD")

#: Union of byte-like types accepted by the encoding helpers.
ByteLike = Union[bytes, bytearray, memoryview]

#: Union of textual types accepted by the encoding helpers.
TextLike = Union[str, ByteLike]


def to_bytes(
    text: TextLike,
    encoding: str = DEFAULT_ENCODING,
    errors: str = ENCODING_ERRORS,
) -> bytes:
    """Return ``text`` encoded as ``bytes``.

    ``bytearray`` and ``memoryview`` are passed through unchanged.  The
    ``encoding`` and ``errors`` arguments mirror :meth:`str.encode` but
    have explicit defaults so test code can rely on a stable contract.
    """

    if isinstance(text, (bytes, bytearray, memoryview)):
        return bytes(text)
    if not isinstance(text, str):
        raise TypeError(
            f"text must be str, bytes, bytearray or memoryview, got {type(text).__name__}"
        )
    return text.encode(encoding, errors)


def from_bytes(
    data: TextLike,
    encoding: str = DEFAULT_ENCODING,
    errors: str = ENCODING_ERRORS,
) -> str:
    """Decode ``data`` using ``encoding`` and return a ``str``.

    Mirrors :meth:`bytes.decode`.  ``bytearray`` and ``memoryview`` are
    accepted because the cipher implementations routinely work with
    either input.
    """

    if isinstance(data, str):
        return data
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"data must be bytes-like, got {type(data).__name__}"
        )
    return bytes(data).decode(encoding, errors)


def normalize(text: str, form: str = "NFC") -> str:
    """Return ``text`` normalised with the given Unicode form.

    The default ``"NFC"`` is what almost every project wants: it
    composes canonical equivalents so the byte representation of two
    visually identical strings matches.  The helper accepts the
    short forms ``"c"`` / ``"d"`` / ``"kc"`` / ``"kd"`` as a
    convenience.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a str")
    aliases: Final[dict[str, str]] = {
        "c": "NFC",
        "d": "NFD",
        "kc": "NFKC",
        "kd": "NFKD",
    }
    resolved: str = aliases.get(form.lower(), form).upper()
    if resolved not in NORMALIZATION_FORMS:
        raise ValueError(
            f"normalization form must be one of {NORMALIZATION_FORMS!r}, got {form!r}"
        )
    return unicodedata.normalize(resolved, text)


def safe_str(data: object, encoding: str = DEFAULT_ENCODING) -> str:
    """Return ``data`` decoded with ``errors='replace'``.

    Useful for logging or error messages that should not raise on
    malformed payloads.  ``str`` input is returned unchanged so the
    helper is safe to chain with the output of :func:`from_bytes`.
    """

    if isinstance(data, str):
        return data
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return repr(data)
    return bytes(data).decode(encoding, errors="replace")


def chunk(text: str, size: int) -> Iterator[str]:
    """Yield successive ``size``-character chunks of ``text``.

    The last chunk may be shorter when ``len(text)`` is not a multiple
    of ``size``.  ``size`` must be a positive integer; a non-positive
    value raises :class:`ValueError` so off-by-one bugs are caught
    early.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a str")
    if not isinstance(size, int) or isinstance(size, bool):
        raise TypeError("size must be a positive int")
    if size <= 0:
        raise ValueError("size must be a positive int")
    for index in range(0, len(text), size):
        yield text[index : index + size]


def codepoint_distribution(text: str) -> List[Tuple[str, int]]:
    """Return a sorted list of ``(char, count)`` pairs for ``text``.

    The helper is primarily intended for inspecting how a cipher
    scrambles an alphabet.  Sorting by descending count (and then by
    code point for stability) keeps the output easy to diff between
    test runs.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a str")
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))
