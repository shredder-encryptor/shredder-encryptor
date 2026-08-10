"""64-bit Feistel block cipher with ECB and CBC modes.

This module provides a small Feistel network that operates on 8-byte
blocks and runs enough rounds to keep the algorithm interesting.  It
is **not secure**: the round function is intentionally simple because
the goal is to demonstrate how to wire :mod:`shredder_encryptor.codec`
and :mod:`shredder_encryptor.framework` together.  Do not use this
cipher for anything that requires real confidentiality.

The cipher ships in two modes:

* :class:`FeistelEcbCipher` -- ECB with PKCS#7 padding.
* :class:`FeistelCbcCipher` -- CBC with PKCS#7 padding and a random
  IV prepended to every cipher text.

Both classes are :class:`shredder_encryptor.framework.BaseCipher`
subclasses and integrate with the shared testing helpers and the
:class:`shredder_encryptor.framework.Pipeline` composer.
"""

from __future__ import annotations

import hashlib
from typing import ClassVar, Final

from ..codec.padding import pkcs7_pad, pkcs7_unpad
from ..codec.token import token_bytes
from ..framework.base import BaseCipher

__all__ = [
    "BLOCK_SIZE",
    "ROUNDS",
    "FeistelEcbCipher",
    "FeistelCbcCipher",
]


#: Block size in bytes.  The Feistel network splits each block in
#: half, so this value must be a multiple of two.
BLOCK_SIZE: Final[int] = 8

#: Number of rounds used by the Feistel network.  Sixteen rounds is
#: enough to make a brute force key recovery impractical against the
#: example round function while keeping the implementation readable.
ROUNDS: Final[int] = 16

#: Multiplier used by the round function.  The constant is odd and
#: relatively prime to 256 so the multiplication provides diffusion.
_ROUND_MULTIPLIER: Final[int] = 0x9D


def _round_function(value: int, round_key: int) -> int:
    """8-bit round function.

    ``value`` and ``round_key`` are unsigned 8-bit integers; the
    result is also 8 bits.
    """

    mixed: int = (value * _ROUND_MULTIPLIER) & 0xFF
    return mixed ^ (round_key & 0xFF)


def _derive_round_keys(key: bytes, rounds: int = ROUNDS) -> list[int]:
    """Expand ``key`` into ``rounds`` 8-bit sub-keys."""

    digest: bytes = hashlib.sha256(key).digest()
    expanded: bytes = (digest * ((rounds // len(digest)) + 1))[:rounds]
    return [expanded[i] for i in range(rounds)]


def _split(block: int) -> tuple[int, int]:
    """Split an 8-byte ``block`` into its left and right 32-bit halves."""

    left: int = (block >> 32) & 0xFFFFFFFF
    right: int = block & 0xFFFFFFFF
    return left, right


def _combine(left: int, right: int) -> int:
    """Combine two 32-bit halves back into an 8-byte value."""

    return ((left & 0xFFFFFFFF) << 32) | (right & 0xFFFFFFFF)


def _feistel_encrypt(block: int, round_keys: list[int]) -> int:
    """Encrypt a single 64-bit ``block``."""

    left, right = _split(block)
    for round_key in round_keys:
        # Apply the round function byte-wise on the right half and mix
        # it into the left half.
        f_value: int = 0
        for byte_index in range(4):
            shift: int = byte_index * 8
            f_byte: int = _round_function(
                (right >> shift) & 0xFF,
                (round_key >> shift) & 0xFF,
            )
            f_value |= f_byte << shift
        left, right = right, left ^ f_value
    # Final swap so encryption and decryption share a single round
    # loop with the round keys used in reverse order.
    left, right = right, left
    return _combine(left, right)


def _feistel_decrypt(block: int, round_keys: list[int]) -> int:
    """Decrypt a single 64-bit ``block``."""

    return _feistel_encrypt(block, list(reversed(round_keys)))


class _FeistelBase(BaseCipher):
    """Shared implementation for the ECB and CBC variants."""

    algorithm: ClassVar[str] = "feistel64"
    DECRYPTABLE: ClassVar[bool] = True

    def __init__(self, key: bytes) -> None:
        key_bytes: bytes = bytes(key)
        if not key_bytes:
            raise ValueError("Feistel key must not be empty")
        if len(key_bytes) > BLOCK_SIZE:
            raise ValueError(f"Feistel key must be at most {BLOCK_SIZE} bytes")
        round_keys: list[int] = _derive_round_keys(key_bytes)
        super().__init__(key=key_bytes, round_keys=round_keys)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"block must be exactly {BLOCK_SIZE} bytes")
        value: int = int.from_bytes(block, "big")
        return _feistel_encrypt(value, self._params["round_keys"]).to_bytes(
            BLOCK_SIZE, "big"
        )

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"block must be exactly {BLOCK_SIZE} bytes")
        value: int = int.from_bytes(block, "big")
        return _feistel_decrypt(value, self._params["round_keys"]).to_bytes(
            BLOCK_SIZE, "big"
        )


class FeistelEcbCipher(_FeistelBase):
    """ECB mode: each block is encrypted independently.

    The output is the concatenation of the encrypted blocks.  PKCS#7
    padding is applied before encryption so the input length is not
    constrained to a multiple of the block size.
    """

    algorithm: ClassVar[str] = "feistel64-ecb"

    def encrypt(self, plaintext: bytes) -> bytes:
        raw: bytes = self._require_bytes(plaintext, "plaintext")
        padded: bytes = pkcs7_pad(raw, BLOCK_SIZE)
        out: bytearray = bytearray(len(padded))
        for offset in range(0, len(padded), BLOCK_SIZE):
            out[offset : offset + BLOCK_SIZE] = self.encrypt_block(
                padded[offset : offset + BLOCK_SIZE]
            )
        return bytes(out)

    def decrypt(self, ciphertext: bytes) -> bytes:
        raw: bytes = self._require_bytes(ciphertext, "ciphertext")
        if len(raw) % BLOCK_SIZE != 0:
            raise ValueError(f"ciphertext length must be a multiple of {BLOCK_SIZE}")
        out: bytearray = bytearray(len(raw))
        for offset in range(0, len(raw), BLOCK_SIZE):
            out[offset : offset + BLOCK_SIZE] = self.decrypt_block(
                raw[offset : offset + BLOCK_SIZE]
            )
        return pkcs7_unpad(bytes(out), BLOCK_SIZE)


class FeistelCbcCipher(_FeistelBase):
    """CBC mode with a random IV prepended to every cipher text.

    The IV is generated with :func:`codec.token.token_bytes` so each
    call produces a unique output, even when the same key encrypts the
    same plaintext twice.  The IV length equals :data:`BLOCK_SIZE`
    which is the AES convention.
    """

    algorithm: ClassVar[str] = "feistel64-cbc"

    def encrypt(self, plaintext: bytes) -> bytes:
        raw: bytes = self._require_bytes(plaintext, "plaintext")
        iv: bytes = token_bytes(BLOCK_SIZE)
        padded: bytes = pkcs7_pad(raw, BLOCK_SIZE)
        out: bytearray = bytearray(len(padded))
        previous: bytes = iv
        for offset in range(0, len(padded), BLOCK_SIZE):
            block: bytes = bytes(padded[offset : offset + BLOCK_SIZE])
            mixed: bytes = bytes(a ^ b for a, b in zip(block, previous))
            encrypted: bytes = self.encrypt_block(mixed)
            out[offset : offset + BLOCK_SIZE] = encrypted
            previous = encrypted
        return iv + bytes(out)

    def decrypt(self, ciphertext: bytes) -> bytes:
        raw: bytes = self._require_bytes(ciphertext, "ciphertext")
        if len(raw) < BLOCK_SIZE * 2 or len(raw) % BLOCK_SIZE != 0:
            raise ValueError("ciphertext is too short or not block-aligned")
        iv, body = raw[:BLOCK_SIZE], raw[BLOCK_SIZE:]
        out: bytearray = bytearray(len(body))
        previous: bytes = iv
        for offset in range(0, len(body), BLOCK_SIZE):
            block: bytes = bytes(body[offset : offset + BLOCK_SIZE])
            decrypted: bytes = self.decrypt_block(block)
            out[offset : offset + BLOCK_SIZE] = bytes(
                a ^ b for a, b in zip(decrypted, previous)
            )
            previous = block
        return pkcs7_unpad(bytes(out), BLOCK_SIZE)
