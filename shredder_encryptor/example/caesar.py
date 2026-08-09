"""Shared implementation of the example Caesar-shift cipher.

Both :class:`SampleEncrypt` and :class:`SampleDecrypt` (re-exported from
:mod:`shredder_encryptor.example.encrypt` and
:mod:`shredder_encryptor.example.decrypt`) are thin wrappers around the
:class:`CaesarShift` engine defined here.  The engine relies on
:meth:`str.translate` with a translation table built once at
construction time, which makes the per-character work O(1) and the
overall complexity of encrypting a string linear in its length.

The cipher is **only** an example used to document the project layout.
Do not use it for anything that requires real confidentiality.
"""

from __future__ import annotations

from .meta import DEFAULT_ALPHABET, validate_alphabet

__all__ = ["CaesarShift", "shift", "make_translation_table"]


def _normalize_offset(offset: int, alphabet_size: int) -> int:
    """Return ``offset`` folded into the half-open range ``[0, size)``.

    The math mirrors ``((offset % size) + size) % size`` which is the
    idiomatic way of normalising a possibly negative Python modulo into
    a non-negative value without changing the cipher semantics.
    """

    return ((int(offset) % alphabet_size) + alphabet_size) % alphabet_size


def make_translation_table(alphabet, offset):
    """Return a ``str.maketrans`` table that shifts ``alphabet``.

    The returned table can be fed straight to :meth:`str.translate`.
    Characters that are not part of the alphabet are mapped to
    themselves so non-Latin text passes through untouched.
    """

    validate_alphabet(alphabet)
    lower, upper = alphabet
    size = len(lower)
    shift = _normalize_offset(offset, size)
    # ``rotate`` keeps the result a permutation of the original string,
    # which is what makes the cipher reversible.
    rotated_lower = lower[shift:] + lower[:shift]
    rotated_upper = upper[shift:] + upper[:shift]
    return str.maketrans(lower + upper, rotated_lower + rotated_upper)


class CaesarShift:
    """Stateful Caesar-shift engine that builds its lookup table once.

    Parameters
    ----------
    offset:
        Signed shift amount.  Negative values shift backwards.  The
        value is normalised internally so values larger than the
        alphabet size behave as if reduced modulo the alphabet length.
    alphabet:
        Optional ``(lower, upper)`` pair.  See :func:`validate_alphabet`
        for the constraints.
    """

    __slots__ = ("offset", "alphabet", "_size", "_table", "_reverse_table")

    def __init__(self, offset=3, alphabet=None) -> None:
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise TypeError("offset must be an int")
        if alphabet is None:
            alphabet = DEFAULT_ALPHABET
        validate_alphabet(alphabet)
        self.offset = offset
        self.alphabet = alphabet
        self._size = len(alphabet[0])
        self._table = make_translation_table(alphabet, offset)
        # Pre-computing the inverse table keeps decryption symmetric
        # with encryption and avoids re-applying ``str.translate`` to
        # the cipher text twice.
        self._reverse_table = make_translation_table(alphabet, -offset)

    def encrypt(self, text):
        if not isinstance(text, str):
            raise TypeError("text must be a str")
        return text.translate(self._table)

    def decrypt(self, cipher_text):
        if not isinstance(cipher_text, str):
            raise TypeError("cipher_text must be a str")
        return cipher_text.translate(self._reverse_table)

    def __repr__(self) -> str:
        return f"CaesarShift(offset={self.offset!r})"

    def __eq__(self, other):
        if not isinstance(other, CaesarShift):
            return NotImplemented
        return self.offset == other.offset and self.alphabet == other.alphabet


def shift(text, offset, alphabet=None):
    """Convenience helper: build a one-shot :class:`CaesarShift` and run it.

    Useful for callers that only need to encrypt a single string and do
    not want to manage the cipher object's lifetime themselves.
    """

    return CaesarShift(offset=offset, alphabet=alphabet).encrypt(text)
