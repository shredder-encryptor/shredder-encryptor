"""XOR stream cipher built on a SHA-256 counter keystream.

The cipher derives a long pseudo-random byte stream by hashing
``key || nonce || counter`` with SHA-256 in counter mode.  The
plaintext is then XORed with that stream.  The construction is
insecure against determined attackers but it is a useful, fully
self-contained demonstration of a reversible :class:`BaseCipher` and
it plays nicely with the :mod:`shredder_encryptor.framework` testing
helpers.
"""

from __future__ import annotations

import hashlib
import struct
from typing import ClassVar

from ..framework.base import BaseCipher

__all__ = ["XorStreamCipher"]


#: Number of bytes produced by a single SHA-256 call.  The constant is
#: used both to slice the keystream and to advance the counter.
_BLOCK_SIZE: int = hashlib.sha256().digest_size


class XorStreamCipher(BaseCipher):
    """Stream cipher that XORs plaintext with a SHA-256 keystream.

    Parameters
    ----------
    key:
        Bytes-like secret used to seed the keystream.  An empty key
        raises :class:`ValueError` because the resulting cipher would
        be trivially breakable.
    nonce:
        Bytes-like value mixed into every keystream block so two
        messages encrypted with the same key do not produce the same
        stream.  A short fixed value is fine for the example use
        case; production code should generate a random nonce per
        message.
    """

    algorithm: ClassVar[str] = "xor-stream"
    DECRYPTABLE: ClassVar[bool] = True

    def __init__(self, key: bytes, *, nonce: bytes = b"shredder") -> None:
        key_bytes: bytes = bytes(key)
        if not key_bytes:
            raise ValueError("XorStreamCipher key must not be empty")
        super().__init__(key=key_bytes, nonce=bytes(nonce))

    # ------------------------------------------------------------------
    # Keystream generation.
    # ------------------------------------------------------------------
    def _keystream(self, length: int) -> bytes:
        """Return ``length`` bytes of pseudo-random material."""

        if length < 0:
            raise ValueError("length must be non-negative")
        key: bytes = self._params["key"]
        nonce: bytes = self._params["nonce"]
        pieces: list[bytes] = []
        counter: int = 0
        produced: int = 0
        while produced < length:
            block: bytes = hashlib.sha256(
                key + nonce + struct.pack(">Q", counter)
            ).digest()
            pieces.append(block)
            produced += _BLOCK_SIZE
            counter += 1
        return b"".join(pieces)[:length]

    # ------------------------------------------------------------------
    # BaseCipher contract.
    # ------------------------------------------------------------------
    def encrypt(self, plaintext: bytes) -> bytes:
        raw: bytes = self._require_bytes(plaintext, "plaintext")
        return bytes(a ^ b for a, b in zip(raw, self._keystream(len(raw))))

    def decrypt(self, ciphertext: bytes) -> bytes:
        # XOR is its own inverse so the implementation is identical.
        return self.encrypt(ciphertext)
