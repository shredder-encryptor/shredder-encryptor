"""Encryption entry point for the example Caesar-shift cipher.

:class:`SampleEncrypt` is a thin wrapper around :class:`CaesarShift`
that pre-configures the default Latin alphabet.  The class keeps the
historical ``offset``/``lower``/``upper`` attributes so existing
callers continue to work, while delegating the actual translation to
the shared engine for performance and consistency.
"""

from __future__ import annotations

from .caesar import CaesarShift
from .meta import DEFAULT_ALPHABET

__all__ = ["SampleEncrypt"]


class SampleEncrypt:
    """Encrypt strings with a configurable Caesar shift."""

    __slots__ = ("_engine", "offset", "lower", "upper")

    def __init__(self, offset: int = 3, alphabet=None) -> None:
        if alphabet is None:
            alphabet = DEFAULT_ALPHABET
        # ``lower``/``upper`` are kept as plain attributes (rather than
        # properties) for backwards compatibility with code that reads
        # them directly.  They mirror the alphabet the engine is using.
        self._engine = CaesarShift(offset=offset, alphabet=alphabet)
        self.offset = self._engine.offset
        lower, upper = self._engine.alphabet
        self.lower = lower
        self.upper = upper

    def encrypt(self, text: str) -> str:
        return self._engine.encrypt(text)

    def __repr__(self) -> str:
        return f"SampleEncrypt(offset={self.offset!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SampleEncrypt):
            return NotImplemented
        return self._engine == other._engine
