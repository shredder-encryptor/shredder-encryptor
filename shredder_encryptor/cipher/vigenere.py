"""Vigenere cipher built on top of :mod:`shredder_encryptor.codec`.

The Vigenere cipher is a classical polyalphabetic substitution cipher
that operates on the bytes of a string by shifting each byte by the
``key`` parameter.  The implementation reuses the encoding helpers
from :mod:`shredder_encryptor.codec.text` so the algorithm can be
applied to UTF-8 text as easily as to raw bytes.

The class inherits from :class:`shredder_encryptor.framework.BaseCipher`
so it integrates with the shared :func:`assert_round_trip` helper and
the :class:`Pipeline` composer.
"""

from __future__ import annotations

from typing import ClassVar, Final

from ..codec.text import ByteLike, TextLike, from_bytes, to_bytes
from ..framework.base import BaseCipher

__all__ = ["VigenereCipher"]


#: The default alphabet used when no explicit one is provided.  The
#: ``bytes`` range ``0..255`` is a natural choice for a byte-oriented
#: polyalphabetic cipher because every possible input byte maps to a
#: unique output byte.
_DEFAULT_ALPHABET_SIZE: Final[int] = 256


class VigenereCipher(BaseCipher):
    """A reversible Vigenere-like cipher working on the byte stream.

    Parameters
    ----------
    key:
        Bytes-like key.  An empty key raises :class:`ValueError` so the
        cipher never silently degenerates into the identity function.
    """

    #: Identifier of the algorithm, consumed by :class:`BaseCipher`.
    algorithm: ClassVar[str] = "vigenere"

    #: The cipher is reversible; the default ``BaseCipher.decrypt``
    #: would raise because it is not implemented.
    DECRYPTABLE: ClassVar[bool] = True

    def __init__(self, key: ByteLike) -> None:
        key_bytes: bytes = bytes(key)
        if not key_bytes:
            raise ValueError("VigenereCipher key must not be empty")
        super().__init__(key=key_bytes)

    # ------------------------------------------------------------------
    # BaseCipher contract.
    # ------------------------------------------------------------------
    def encrypt(self, plaintext: bytes) -> bytes:
        raw: bytes = self._require_bytes(plaintext, "plaintext")
        key: bytes = self._params["key"]
        out: bytearray = bytearray(len(raw))
        for index, byte in enumerate(raw):
            out[index] = (byte + key[index % len(key)]) % _DEFAULT_ALPHABET_SIZE
        return bytes(out)

    def decrypt(self, ciphertext: bytes) -> bytes:
        raw: bytes = self._require_bytes(ciphertext, "ciphertext")
        key: bytes = self._params["key"]
        out: bytearray = bytearray(len(raw))
        for index, byte in enumerate(raw):
            out[index] = (byte - key[index % len(key)]) % _DEFAULT_ALPHABET_SIZE
        return bytes(out)

    # ------------------------------------------------------------------
    # String-flavoured helpers built on top of :mod:`codec.text`.
    # ------------------------------------------------------------------
    def encrypt_text(self, text: TextLike) -> bytes:
        """Encode ``text`` as UTF-8 and encrypt the bytes."""

        return self.encrypt(to_bytes(text))

    def decrypt_text(self, payload: ByteLike) -> str:
        """Decrypt ``payload`` and decode the result as UTF-8."""

        return from_bytes(self.decrypt(payload))
