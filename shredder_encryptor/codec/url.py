"""URL encoding helpers backed by :mod:`urllib.parse`.

The module exposes two flavours:

* :func:`quote` / :func:`unquote` -- percent-encoding for a single
  component (RFC 3986).
* :func:`urlencode` / :func:`urldecode` -- the
  ``application/x-www-form-urlencoded`` form used by HTML form
  submissions.

Every function accepts both ``str`` and ``bytes`` and returns the
type that was passed in.  ``safe`` defaults follow the Python
standard library so behaviour matches expectations.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Final
from urllib.parse import (
    parse_qsl,
    quote as _stdlib_quote,
    quote_from_bytes,
    unquote as _stdlib_unquote,
    unquote_plus,
    urlencode as _stdlib_urlencode,
)

from .text import TextLike

__all__ = [
    "DEFAULT_SAFE",
    "DEFAULT_ENCODING",
    "quote",
    "unquote",
    "urlencode",
    "urldecode",
]


#: Characters that are *always* considered safe to leave un-escaped.
#: This matches :data:`urllib.parse.DEFAULT_SAFE` (which excludes the
#: slash); a separate constant makes it easy to extend.
DEFAULT_SAFE: Final[str] = "/"

#: Encoding used by :func:`quote` and :func:`unquote` when the input
#: is a ``str``.
DEFAULT_ENCODING: Final[str] = "utf-8"


def quote(
    text: TextLike,
    safe: str = DEFAULT_SAFE,
    encoding: str = DEFAULT_ENCODING,
    errors: str = "strict",
) -> str:
    """Percent-encode ``text``.

    Strings are encoded with ``encoding`` before being escaped;
    bytes are escaped verbatim.  ``safe`` lists characters that must
    not be escaped.
    """

    if isinstance(text, (bytes, bytearray, memoryview)):
        return quote_from_bytes(bytes(text), safe=safe)
    if not isinstance(text, str):
        raise TypeError(f"text must be str or bytes-like, got {type(text).__name__}")
    return _stdlib_quote(text, safe=safe, encoding=encoding, errors=errors)


def unquote(
    text: TextLike,
    encoding: str = DEFAULT_ENCODING,
    errors: str = "strict",
) -> str:
    """Reverse :func:`quote`` for a single component."""

    if isinstance(text, (bytes, bytearray, memoryview)):
        text = bytes(text).decode("ascii", errors=errors)
    if not isinstance(text, str):
        raise TypeError(f"text must be str or bytes-like, got {type(text).__name__}")
    return _stdlib_unquote(text, encoding=encoding, errors=errors)


def urlencode(
    query: Mapping[str, object] | Iterable[tuple[str, object]],
    *,
    doseq: bool = False,
    safe: str = DEFAULT_SAFE,
    encoding: str = DEFAULT_ENCODING,
    errors: str = "strict",
) -> str:
    """Encode a mapping or iterable of pairs as a query string."""

    if not isinstance(query, (Mapping, Iterable)):
        raise TypeError("query must be a Mapping or an iterable of (key, value) pairs")
    return _stdlib_urlencode(
        query,
        doseq=doseq,
        safe=safe,
        encoding=encoding,
        errors=errors,
    )


def urldecode(
    text: TextLike,
    *,
    keep_blank_values: bool = False,
    strict_parsing: bool = False,
    encoding: str = DEFAULT_ENCODING,
    errors: str = "strict",
    max_num_fields: int | None = None,
) -> list[tuple[str, str]]:
    """Parse a query string and return a list of ``(key, value)`` pairs.

    Plus signs are converted to spaces (``application/x-www-form-urlencoded``
    semantics).  Pass ``unquote_plus`` yourself if you need the raw
    ``+`` characters.
    """

    if isinstance(text, (bytes, bytearray, memoryview)):
        text = bytes(text).decode("ascii", errors=errors)
    if not isinstance(text, str):
        raise TypeError(f"text must be str or bytes-like, got {type(text).__name__}")
    decoded = unquote_plus(text, encoding=encoding, errors=errors)
    pairs: Iterable[tuple[str, str]] = parse_qsl(
        decoded,
        keep_blank_values=keep_blank_values,
        strict_parsing=strict_parsing,
        encoding=encoding,
        errors=errors,
        max_num_fields=max_num_fields,
    )
    return list(pairs)
