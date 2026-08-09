"""A 16-bit Feistel-network block cipher with PKCS#7 padding.

The implementation is intentionally small: it operates on 2-byte
blocks using four rounds of a simple XOR-and-rotate round function.
The cipher is suitable as a teaching example and as a way to exercise
:mod:`shredder_encryptor.codec.padding` and the :class:`BaseCipher`
machinery from the framework package.  Do not use it for anything
that requires real confidentiality.
"""

from __future__ import annotations

from typing import ClassVar, Final

from ..codec.padding import pkcs7_pad, pkcs7_unpad
from ..framework.base import BaseCipher

__all__ = ["ToyFeistelCipher"]


#: Block size in bytes.  Feistel networks must split a block in half,
#: so the value must be a power of two.  Two bytes is enough to keep
#: the test vectors readable.
BLOCK_SIZE: Final[int] = 2

#: Number of Feistel rounds.  Four is more than enough for an
#: illustrative cipher and keeps the implementation tight.
_ROUNDS: Final[int] = 4


def _round_function(value: int, round_key: int) -> int:
    """Apply the round function ``f(value, round_key)``.

    ``value`` and ``round_key`` are 8-bit unsigned integers; the result
    is also 8 bits.  The function is intentionally simple because the
    cipher is an example, not a production algorithm: a multiplication
    by a small constant provides diffusion and the XOR mixes the round
    key into the output.
    """

    mixed: int = (value * 0x5B) & 0xFF
    return mixed ^ (round_key & 0xFF)


def _derive_round_keys(key: bytes) -> list[int]:
    """Expand ``key`` into ``_ROUNDS`` 8-bit round keys."""

    import hashlib

    digest: bytes = hashlib.sha256(key).digest()
    return [digest[i] for i in range(_ROUNDS)]


def _feistel_block(block: int, round_keys: list[int], *, inverse: bool) -> int:
    """Encrypt or decrypt a single 16-bit ``block``.

    Each round updates the state as
    ``(L, R) -> (R, L XOR f(R, K_i))``.  After the last round the
    two halves are swapped so the cipher and the inverse cipher can
    share the same round loop with the round keys used in reverse
    order.
    """

    left: int = (block >> 8) & 0xFF
    right: int = block & 0xFF
    keys: list[int] = list(reversed(round_keys)) if inverse else list(round_keys)
    for round_key in keys:
        new_right: int = left ^ _round_function(right, round_key)
        left, right = right, new_right
    # Both the encryption and the decryption paths apply the same
    # final swap.  The decryption path uses the round keys in reverse
    # order, which is what makes the swap recover the original input
    # rather than swapping it.
    left, right = right, left
    return ((left & 0xFF) << 8) | (right & 0xFF)


class ToyFeistelCipher(BaseCipher):
    """A toy 16-bit Feistel cipher with PKCS#7 padding.

    Parameters
    ----------
    key:
        Bytes-like key used to derive the round keys.  An empty key
        raises :class:`ValueError` so the cipher never degenerates
        into a public permutation.
    """

    algorithm: ClassVar[str] = "toy-feistel-16"
    DECRYPTABLE: ClassVar[bool] = True

    def __init__(self, key: bytes) -> None:
        key_bytes: bytes = bytes(key)
        if not key_bytes:
            raise ValueError("ToyFeistelCipher key must not be empty")
        round_keys: list[int] = _derive_round_keys(key_bytes)
        super().__init__(key=key_bytes, round_keys=round_keys)

    # ------------------------------------------------------------------
    # Single-block helpers, exposed for unit tests.
    # ------------------------------------------------------------------
    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"block must be exactly {BLOCK_SIZE} bytes")
        value: int = int.from_bytes(block, "big")
        return _feistel_block(value, self._params["round_keys"], inverse=False).to_bytes(
            BLOCK_SIZE, "big"
        )

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"block must be exactly {BLOCK_SIZE} bytes")
        value: int = int.from_bytes(block, "big")
        return _feistel_block(value, self._params["round_keys"], inverse=True).to_bytes(
            BLOCK_SIZE, "big"
        )

    # ------------------------------------------------------------------
    # BaseCipher contract (operates on the whole buffer).
    # ------------------------------------------------------------------
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
            raise ValueError(
                f"ciphertext length must be a multiple of {BLOCK_SIZE}"
            )
        out: bytearray = bytearray(len(raw))
        for offset in range(0, len(raw), BLOCK_SIZE):
            out[offset : offset + BLOCK_SIZE] = self.decrypt_block(
                raw[offset : offset + BLOCK_SIZE]
            )
        return pkcs7_unpad(bytes(out), BLOCK_SIZE)
