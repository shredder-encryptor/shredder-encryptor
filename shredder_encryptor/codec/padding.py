"""Block-padding helpers.

The module provides two strategies used by the example ciphers:

* :func:`pkcs7_pad` / :func:`pkcs7_unpad` implement PKCS#7 padding.
  The padded message is always a multiple of ``block_size`` and the
  last ``n`` bytes (where ``1 <= n <= block_size``) carry the value
  ``n`` so the padding is unambiguous.
* :func:`zero_pad` / :func:`zero_unpad` implement a simpler zero-byte
  padding strategy that is not safe for binary data but is convenient
  for ASCII inputs.

Both functions validate their inputs aggressively so misconfigured
block sizes or corrupt cipher texts surface as :class:`ValueError`
rather than silent data loss.
"""

from __future__ import annotations

from typing import Final

from .text import ByteLike

__all__ = [
    "MIN_BLOCK_SIZE",
    "MAX_BLOCK_SIZE",
    "pkcs7_pad",
    "pkcs7_unpad",
    "is_pkcs7_padded",
    "zero_pad",
    "zero_unpad",
    "required_padding_length",
]


#: Smallest block size the padding helpers will accept.  Anything
#: smaller would not be able to encode the padding length itself.
MIN_BLOCK_SIZE: Final[int] = 2

#: Largest block size the padding helpers will accept.  Capping the
#: value protects against pathologically large allocations triggered
#: by user-supplied parameters.
MAX_BLOCK_SIZE: Final[int] = 1 << 16  # 64 KiB


def _validate_block_size(block_size: int) -> int:
    """Return ``block_size`` when it is in the allowed range."""

    if not isinstance(block_size, int) or isinstance(block_size, bool):
        raise TypeError(f"block_size must be an int, got {type(block_size).__name__}")
    if block_size < MIN_BLOCK_SIZE or block_size > MAX_BLOCK_SIZE:
        raise ValueError(
            f"block_size must be between {MIN_BLOCK_SIZE} and {MAX_BLOCK_SIZE}"
        )
    return block_size


def required_padding_length(data_length: int, block_size: int) -> int:
    """Return the number of padding bytes required to align ``data_length``.

    The result is always between ``1`` and ``block_size`` so PKCS#7
    padding can disambiguate the trailing bytes after unpadding.
    """

    if not isinstance(data_length, int) or isinstance(data_length, bool):
        raise TypeError(f"data_length must be an int, got {type(data_length).__name__}")
    if data_length < 0:
        raise ValueError("data_length must be non-negative")
    _validate_block_size(block_size)
    remainder: int = data_length % block_size
    if remainder == 0:
        return block_size
    return block_size - remainder


def pkcs7_pad(data: ByteLike, block_size: int) -> bytes:
    """Return ``data`` padded with PKCS#7 to a multiple of ``block_size``."""

    _validate_block_size(block_size)
    payload: bytes = bytes(data)
    pad_length: int = required_padding_length(len(payload), block_size)
    return payload + bytes([pad_length]) * pad_length


def pkcs7_unpad(data: ByteLike, block_size: int) -> bytes:
    """Remove the PKCS#7 padding from ``data``."""

    _validate_block_size(block_size)
    payload: bytes = bytes(data)
    if not payload:
        raise ValueError("cannot unpad empty data")
    if len(payload) % block_size != 0:
        raise ValueError("padded data length is not a multiple of block_size")
    pad_length: int = payload[-1]
    if pad_length == 0 or pad_length > block_size:
        raise ValueError("padding length is out of range")
    if payload[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("padding bytes are not consistent")
    return payload[:-pad_length]


def is_pkcs7_padded(data: ByteLike, block_size: int) -> bool:
    """Return ``True`` when ``data`` looks like a PKCS#7 padded buffer."""

    try:
        pkcs7_unpad(data, block_size)
    except ValueError:
        return False
    return True


def zero_pad(data: ByteLike, block_size: int) -> bytes:
    """Return ``data`` padded with zero bytes to ``block_size``.

    Unlike PKCS#7 the padded output does not encode the original
    length, which is why :func:`zero_unpad` strips any trailing
    zero bytes.  Use this helper only when the input is known not to
    end in zero bytes.
    """

    _validate_block_size(block_size)
    payload: bytes = bytes(data)
    if len(payload) % block_size == 0:
        return payload
    pad_length: int = block_size - (len(payload) % block_size)
    return payload + b"\x00" * pad_length


def zero_unpad(data: ByteLike) -> bytes:
    """Strip trailing zero bytes from ``data``."""

    payload: bytes = bytes(data)
    index: int = len(payload)
    while index > 0 and payload[index - 1] == 0:
        index -= 1
    return payload[:index]
