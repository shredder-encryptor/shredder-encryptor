"""Stride-based one-way downsampler.

This module ships :class:`DiscardCipher`, an irreversible transform
that drops every ``N``-th byte of the input.  The cipher produces a
shorter stream that cannot be extended back to the original; the
missing bytes are simply gone.

The class is integrated with :mod:`shredder_encryptor.framework` and
inherits from :class:`BaseCipher`.  ``DECRYPTABLE`` is ``False`` so no
decrypt attempt can succeed.

Typical use::

    from shredder_encryptor.boom import DiscardCipher

    cipher = DiscardCipher(step=4, offset=0)
    digest = cipher.encrypt(b"abcdefghijklmnop")  # b"aeimq..."
"""

from __future__ import annotations

from typing import ClassVar, Final

from ..codec.b64 import encode as b64_encode
from ..codec.hexutil import to_hex
from ..framework.base import BaseCipher

__all__ = ["DiscardCipher", "DEFAULT_STEP"]


#: Default stride used when no explicit step is provided.  The value
#: keeps every byte by default (so the behaviour is the most
#: conservative possible) and demonstrates that ``step=1`` is a
#: valid degenerate case.
DEFAULT_STEP: Final[int] = 2


class DiscardCipher(BaseCipher):
    """One-way cipher that drops every ``N``-th byte of the input.

    Parameters
    ----------
    step:
        Stride of the subsampler.  Must be a positive integer.  When
        ``step == 1`` every byte is kept; when ``step == 2`` the
        cipher keeps bytes at positions ``0, 2, 4, ...``; and so on.
    offset:
        Optional shift applied to the position counter before the
        modulo check.  ``offset`` must be a non-negative integer
        smaller than ``step``.  Negative or unbounded offsets lead
        to ambiguous end-of-stream behaviour and are rejected.

    The output length is ``ceil((len(input) - offset) / step)`` which
    is strictly less than the input length whenever ``step > 1`` and
    the input is long enough.  The discarded bytes are never
    captured, so the original buffer cannot be recovered.
    """

    algorithm: ClassVar[str] = "discard"
    DECRYPTABLE: ClassVar[bool] = False

    def __init__(self, step: int = DEFAULT_STEP, *, offset: int = 0) -> None:
        if not isinstance(step, int) or isinstance(step, bool):
            raise TypeError(f"step must be an int, got {type(step).__name__}")
        if step <= 0:
            raise ValueError("step must be a positive integer")
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise TypeError(f"offset must be an int, got {type(offset).__name__}")
        if offset < 0 or offset >= step:
            raise ValueError(f"offset must be in the range [0, step), got {offset!r}")
        super().__init__(step=step, offset=offset)

    def encrypt(self, plaintext: bytes) -> bytes:
        raw: bytes = self._require_bytes(plaintext, "plaintext")
        step: int = self._params["step"]
        offset: int = self._params["offset"]
        return bytes(raw[index] for index in range(offset, len(raw), step))

    def encrypt_hex(self, plaintext: bytes) -> str:
        """Return the subsampled cipher text as a lower-case hex string."""

        return to_hex(self.encrypt(plaintext))

    def encrypt_b64(self, plaintext: bytes) -> str:
        """Return the subsampled cipher text base64-encoded."""

        return b64_encode(self.encrypt(plaintext))
