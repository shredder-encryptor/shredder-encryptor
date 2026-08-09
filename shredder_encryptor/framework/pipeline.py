"""Compose multiple ciphers into a reversible pipeline.

The :class:`Pipeline` helper applies a list of ciphers in order when
encrypting and in reverse order when decrypting.  Module-level
helpers :func:`encrypt` and :func:`decrypt` are provided for one-shot
use.

The pipeline is intentionally simple: every cipher in the list is
assumed to be reversible.  Mixing in a one-way cipher (where
``DECRYPTABLE`` is ``False``) raises :class:`CipherError` either
immediately or on the matching ``decrypt`` call, depending on which
side detects the problem.
"""

from __future__ import annotations

from collections.abc import Iterable

from .base import BaseCipher, CipherError

__all__ = ["Pipeline", "encrypt", "decrypt"]


class Pipeline:
    """A composable sequence of :class:`BaseCipher` instances."""

    __slots__ = ("_ciphers",)

    def __init__(self, ciphers: Iterable[BaseCipher] = ()) -> None:
        ordered: list[BaseCipher] = list(ciphers)
        for cipher in ordered:
            if not isinstance(cipher, BaseCipher):
                raise CipherError(
                    f"pipeline members must be BaseCipher instances, got {type(cipher).__name__}"
                )
        self._ciphers: list[BaseCipher] = ordered

    @property
    def DECRYPTABLE(self) -> bool:  # noqa: N802 - match BaseCipher spelling
        """Return ``True`` only when every member is reversible."""

        return all(cipher.DECRYPTABLE for cipher in self._ciphers)

    @property
    def algorithm(self) -> str:
        return "+".join(
            cipher.algorithm or type(cipher).__name__ for cipher in self._ciphers
        )

    def __len__(self) -> int:
        return len(self._ciphers)

    def __iter__(self):
        return iter(self._ciphers)

    def __getitem__(self, index: int) -> BaseCipher:
        return self._ciphers[index]

    def __add__(self, other: "Pipeline | BaseCipher") -> "Pipeline":
        if isinstance(other, Pipeline):
            return Pipeline(self._ciphers + other._ciphers)
        if isinstance(other, BaseCipher):
            return Pipeline(self._ciphers + [other])
        raise TypeError(
            f"can only concatenate Pipeline or BaseCipher (not {type(other).__name__})"
        )

    def __radd__(self, other: "Pipeline | BaseCipher") -> "Pipeline":
        if isinstance(other, Pipeline):
            return Pipeline(other._ciphers + self._ciphers)
        if isinstance(other, BaseCipher):
            return Pipeline([other] + self._ciphers)
        raise TypeError(
            f"can only concatenate Pipeline or BaseCipher (not {type(other).__name__})"
        )

    def __repr__(self) -> str:
        return f"Pipeline({self._ciphers!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Pipeline):
            return NotImplemented
        return self._ciphers == other._ciphers

    def append(self, cipher: BaseCipher) -> "Pipeline":
        """Return a new pipeline with ``cipher`` appended."""

        if not isinstance(cipher, BaseCipher):
            raise CipherError(
                f"pipeline members must be BaseCipher instances, got {type(cipher).__name__}"
            )
        return Pipeline(self._ciphers + [cipher])

    def encrypt(self, plaintext: bytes) -> bytes:
        """Run every cipher in order, feeding the output of one into the next."""

        data: bytes = bytes(plaintext)
        for index, cipher in enumerate(self._ciphers):
            data = cipher.encrypt(data)
            if not isinstance(data, (bytes, bytearray, memoryview)):
                raise CipherError(
                    f"cipher #{index} ({cipher.name}) did not return bytes"
                )
        return data

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Reverse the pipeline; every cipher must be reversible."""

        data: bytes = bytes(ciphertext)
        for index, cipher in enumerate(reversed(self._ciphers)):
            if not cipher.DECRYPTABLE:
                raise CipherError(f"cipher #{index} ({cipher.name}) is not reversible")
            data = cipher.decrypt(data)
            if not isinstance(data, (bytes, bytearray, memoryview)):
                raise CipherError(
                    f"cipher #{index} ({cipher.name}) did not return bytes"
                )
        return data


def encrypt(plaintext: bytes, *ciphers: BaseCipher) -> bytes:
    """Run ``ciphers`` in order on ``plaintext`` and return the cipher text."""

    return Pipeline(ciphers).encrypt(plaintext)


def decrypt(ciphertext: bytes, *ciphers: BaseCipher) -> bytes:
    """Reverse the ciphers produced by :func:`encrypt`."""

    return Pipeline(ciphers).decrypt(ciphertext)
