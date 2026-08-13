"""Length-reducing one-way cipher.

This module ships :class:`TruncateCipher`, the simplest irreversible
transform in :mod:`shredder_encryptor.boom`.  The cipher keeps either
the first or the last ``keep`` bytes of the plaintext and discards the
rest, so the original buffer cannot be recovered from the output.

The class is integrated with :mod:`shredder_encryptor.framework` and
inherits from :class:`BaseCipher`.  Because ``DECRYPTABLE`` is
``False`` the standard :func:`assert_irreversible` helper can be used
to verify that the cipher refuses every decrypt call.

Typical use::

    from shredder_encryptor.boom import TruncateCipher, KEEP_HEAD

    cipher = TruncateCipher(keep=16, side=KEEP_HEAD)
    digest = cipher.encrypt(b"a long payload that will be truncated")
    # ``digest`` is at most 16 bytes long; the discarded bytes are
    # gone for good.
"""

from __future__ import annotations

from typing import ClassVar, Final

from ..codec.b64 import encode as b64_encode
from ..codec.hexutil import to_hex
from ..framework.base import BaseCipher

__all__ = ["TruncateCipher", "KEEP_HEAD", "KEEP_TAIL"]


#: Keep the leading ``keep`` bytes of the plaintext.
KEEP_HEAD: Final[str] = "head"

#: Keep the trailing ``keep`` bytes of the plaintext.
KEEP_TAIL: Final[str] = "tail"

#: Valid ``side`` values accepted by :class:`TruncateCipher`.
_VALID_SIDES: Final[tuple[str, ...]] = (KEEP_HEAD, KEEP_TAIL)


class TruncateCipher(BaseCipher):
    """One-way cipher that retains only a prefix or suffix of the input.

    Parameters
    ----------
    keep:
        Number of bytes to keep.  Must be a positive integer.  The
        cipher returns at most ``keep`` bytes; inputs shorter than
        ``keep`` are returned unchanged after a copy.
    side:
        Either :data:`KEEP_HEAD` (default) or :data:`KEEP_TAIL`.  Any
        other value raises :class:`ValueError`.

    The result of :meth:`encrypt` is always a contiguous slice of the
    input.  Because the discarded bytes are never captured anywhere,
    there is no way (short of guessing) to recover the original
    payload from the cipher text.
    """

    algorithm: ClassVar[str] = "truncate"
    DECRYPTABLE: ClassVar[bool] = False

    def __init__(self, keep: int, *, side: str = KEEP_HEAD) -> None:
        if not isinstance(keep, int) or isinstance(keep, bool):
            raise TypeError(f"keep must be an int, got {type(keep).__name__}")
        if keep <= 0:
            raise ValueError("keep must be a positive integer")
        if side not in _VALID_SIDES:
            raise ValueError(f"side must be one of {_VALID_SIDES!r}, got {side!r}")
        super().__init__(keep=keep, side=side)

    def encrypt(self, plaintext: bytes) -> bytes:
        raw: bytes = self._require_bytes(plaintext, "plaintext")
        keep: int = self._params["keep"]
        if self._params["side"] == KEEP_HEAD:
            return raw[:keep]
        return raw[-keep:] if keep <= len(raw) else raw

    def encrypt_hex(self, plaintext: bytes) -> str:
        """Return the truncated cipher text as a lower-case hex string."""

        return to_hex(self.encrypt(plaintext))

    def encrypt_b64(self, plaintext: bytes) -> str:
        """Return the truncated cipher text base64-encoded."""

        return b64_encode(self.encrypt(plaintext))
