"""Test helpers shared by every cipher implementation.

The functions in this module are intentionally tiny so the unit
tests in :mod:`tests` can exercise a new cipher with a single
``assert_round_trip`` call.  They raise :class:`AssertionError` (or
the cipher's own error class) so a failing test prints a helpful
message instead of a generic traceback.
"""

from __future__ import annotations

import random
from collections.abc import Iterable

from .base import BaseCipher, CipherError

__all__ = [
    "assert_round_trip",
    "assert_irreversible",
    "fuzz_cipher",
    "random_bytes",
]


def assert_round_trip(
    cipher: BaseCipher,
    plaintext: bytes,
    *,
    expected: bytes | None = None,
    message: str = "",
) -> None:
    """Assert that ``cipher.decrypt(cipher.encrypt(plaintext)) == plaintext``.

    ``expected`` lets callers check the produced cipher text against
    a golden value; this is useful for deterministic ciphers.
    """

    cipher_text: bytes = cipher.encrypt(plaintext)
    if expected is not None and cipher_text != expected:
        raise AssertionError(
            f"{message or 'cipher text mismatch'}: got {cipher_text!r}, expected {expected!r}"
        )
    if not cipher.DECRYPTABLE:
        raise AssertionError(
            f"{message or 'cipher reports DECRYPTABLE=False'} but a round trip was attempted"
        )
    recovered: bytes = cipher.decrypt(cipher_text)
    if recovered != plaintext:
        raise AssertionError(
            f"{message or 'round trip failed'}: encrypt produced {cipher_text!r}, "
            f"decrypt returned {recovered!r}, expected {plaintext!r}"
        )


def assert_irreversible(cipher: BaseCipher, plaintext: bytes) -> None:
    """Assert that ``cipher`` refuses to decrypt and produces a digest."""

    if cipher.DECRYPTABLE:
        raise AssertionError(
            "cipher reports DECRYPTABLE=True but a one-way test was requested"
        )
    digest: bytes = cipher.encrypt(plaintext)
    if not isinstance(digest, (bytes, bytearray, memoryview)):
        raise AssertionError(
            f"digest must be bytes-like, got {type(digest).__name__}"
        )
    try:
        cipher.decrypt(digest)  # type: ignore[attr-defined]
    except CipherError:
        return
    raise AssertionError(
        "one-way cipher unexpectedly accepted a decrypt() call"
    )


def random_bytes(
    length: int,
    *,
    seed: int | None = None,
    max_byte: int = 256,
) -> bytes:
    """Return ``length`` pseudo-random bytes.

    ``seed`` makes the output deterministic when a test needs a
    reproducible input.  ``max_byte`` is exposed so tests can
    generate ASCII-only inputs by passing ``128`` (or any other
    upper bound) instead of always relying on the full byte range.
    """

    if length < 0:
        raise ValueError("length must be non-negative")
    if not (1 <= max_byte <= 256):
        raise ValueError("max_byte must be between 1 and 256")
    rng: random.Random = random.Random(seed)
    return bytes(rng.randrange(max_byte) for _ in range(length))


def fuzz_cipher(
    cipher: BaseCipher,
    inputs: Iterable[bytes],
    *,
    iterations: int = 32,
) -> list[bytes]:
    """Run ``assert_round_trip`` on every input ``iterations`` times.

    The function returns the list of cipher texts produced (one per
    input) so callers can do additional structural checks.  A
    reversible cipher must always decrypt back to the original
    plaintext, regardless of how many times the round trip is
    repeated.
    """

    if not isinstance(iterations, int) or iterations < 1:
        raise ValueError("iterations must be a positive int")
    results: list[bytes] = []
    for plain in inputs:
        for _ in range(iterations):
            assert_round_trip(cipher, plain)
        results.append(cipher.encrypt(plain))
    return results
