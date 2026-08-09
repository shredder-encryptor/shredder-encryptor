"""Alphabet definitions used by the example Caesar-shift cipher.

The constants are kept as module level strings so they can be shared
between the encryptor and decryptor without paying the cost of
rebuilding the alphabet on every call.  Callers that need a custom
alphabet should pass an explicit ``alphabet`` pair to the
:class:`~shredder_encryptor.example.caesar.CaesarShift` factory rather
than mutating the defaults.
"""

from __future__ import annotations

from typing import Tuple

#: Lowercase Latin alphabet used as the default shift table.
LOWER: str = "abcdefghijklmnopqrstuvwxyz"

#: Uppercase Latin alphabet used as the default shift table.
UPPER: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#: Default alphabet pair ``(lower, upper)`` consumed by the example
#: cipher.  Exporting the tuple (instead of two separate constants)
#: keeps the two strings in lockstep so a typo in one place is caught
#: by :func:`validate_alphabet`.
DEFAULT_ALPHABET: Tuple[str, str] = (LOWER, UPPER)


def validate_alphabet(alphabet):
    """Return ``alphabet`` unchanged when it can be used safely.

    The two strings must be non-empty, equal in length and contain
    unique characters.  These checks guarantee that the lookup table
    built from the alphabet is a bijection, which is what makes the
    cipher reversible.
    """

    if not isinstance(alphabet, tuple) or len(alphabet) != 2:
        raise ValueError("alphabet must be a tuple of (lower, upper) strings")
    lower, upper = alphabet
    if not isinstance(lower, str) or not isinstance(upper, str):
        raise ValueError("alphabet entries must be strings")
    if not lower or not upper:
        raise ValueError("alphabet entries must not be empty")
    if len(lower) != len(upper):
        raise ValueError("alphabet entries must have the same length")
    if len(set(lower)) != len(lower):
        raise ValueError("lower alphabet must not contain duplicate characters")
    if len(set(upper)) != len(upper):
        raise ValueError("upper alphabet must not contain duplicate characters")
    if set(lower) & set(upper):
        raise ValueError("lower and upper alphabets must not share characters")
    return alphabet
