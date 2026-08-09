"""Decryption entry point for the example Caesar-shift cipher.

Mirror of :class:`SampleEncrypt` that uses the same :class:`CaesarShift`
engine.  The wrapper keeps the original ``offset``/``lower``/``upper``
attributes so that any caller introspecting a ``SampleDecrypt`` keeps
working after the optimisation.
"""

from __future__ import annotations

from .caesar import CaesarShift
from .meta import DEFAULT_ALPHABET

__all__ = ["SampleDecrypt"]


class SampleDecrypt:
    """Decrypt strings produced by :class:`SampleEncrypt`."""

    __slots__ = ("_engine", "offset", "lower", "upper")

    def __init__(self, offset: int = 3, alphabet=None) -> None:
        if alphabet is None:
            alphabet = DEFAULT_ALPHABET
        self._engine = CaesarShift(offset=offset, alphabet=alphabet)
        self.offset = self._engine.offset
        lower, upper = self._engine.alphabet
        self.lower = lower
        self.upper = upper

    def decrypt(self, cipher_text: str) -> str:
        return self._engine.decrypt(cipher_text)

    def __repr__(self) -> str:
        return f"SampleDecrypt(offset={self.offset!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SampleDecrypt):
            return NotImplemented
        return self._engine == other._engine
