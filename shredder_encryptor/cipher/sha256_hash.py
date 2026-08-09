"""One-way SHA-256 hash demonstrating a non-decryptable cipher.

This module exists primarily to show how a cipher module fits into
:mod:`shredder_encryptor.framework` when the algorithm is not
reversible.  The class sets ``DECRYPTABLE = False`` and overrides
:func:`verify` so the standard testing helpers can be used without
triggering the default ``raise CipherError`` behaviour.
"""

from __future__ import annotations

import hashlib
from typing import ClassVar

from ..codec.hexutil import from_hex, to_hex
from ..framework.base import BaseCipher

__all__ = ["Sha256Hash"]


class Sha256Hash(BaseCipher):
    """Non-reversible wrapper around :func:`hashlib.sha256`.

    Parameters
    ----------
    salt:
        Optional bytes prepended to the plaintext before hashing.
        Using a random salt per record makes pre-computed tables
        impractical for small inputs.
    """

    algorithm: ClassVar[str] = "sha256"
    DECRYPTABLE: ClassVar[bool] = False

    def __init__(self, *, salt: bytes = b"") -> None:
        super().__init__(salt=bytes(salt))

    # ------------------------------------------------------------------
    # BaseCipher contract.
    # ------------------------------------------------------------------
    def encrypt(self, plaintext: bytes) -> bytes:
        raw: bytes = self._require_bytes(plaintext, "plaintext")
        return hashlib.sha256(self._params["salt"] + raw).digest()

    def verify(self, plaintext: bytes, digest: bytes) -> bool:
        clean_plain: bytes = self._require_bytes(plaintext, "plaintext")
        clean_digest: bytes = self._require_bytes(digest, "digest")
        return self.encrypt(clean_plain) == clean_digest

    # ------------------------------------------------------------------
    # String-flavoured helpers built on top of :mod:`codec.hexutil`.
    # ------------------------------------------------------------------
    def encrypt_hex(self, plaintext: bytes) -> str:
        """Return the digest as a lower-case hexadecimal string."""

        return to_hex(self.encrypt(plaintext))

    def verify_hex(self, plaintext: bytes, hex_digest: str) -> bool:
        return self.verify(plaintext, from_hex(hex_digest))
