"""ASCII85 / Base85 encodings.

Two variants are exposed:

* :func:`encode_ascii85` / :func:`decode_ascii85` -- the Adobe / btoa
  flavour wrapped in ``<~`` / ``~>`` markers.
* :func:`encode_ascii85_adb` / :func:`decode_ascii85_adb` -- the
  Git/PHP ``ascii85`` flavour without markers and a 4-space folded
  output.

Both round-trip arbitrary bytes.
"""

from __future__ import annotations

import base64
import struct

from .text import ByteLike

__all__ = [
    "encode_ascii85",
    "decode_ascii85",
    "encode_ascii85_adb",
    "decode_ascii85_adb",
]


def encode_ascii85(data: ByteLike, *, wrap: int = 76) -> bytes:
    """Return ``data`` encoded as Adobe-style ASCII85."""

    payload: bytes = bytes(data)
    # ``base64.a85encode`` exposes ``wrapcol`` (not ``wrap``); forward
    # ``wrap`` under the right name so callers can keep using the
    # familiar keyword.
    return base64.a85encode(payload, wrapcol=wrap, adobe=True)


def decode_ascii85(data: ByteLike, *, adobe: bool = True) -> bytes:
    """Decode ``data`` produced by :func:`encode_ascii85`."""

    payload: bytes = bytes(data)
    return base64.a85decode(payload, adobe=adobe, ignorechars=b"\n\r\t ")


def encode_ascii85_adb(data: ByteLike, *, foldspaces: bool = False) -> bytes:
    """Return ``data`` encoded with the Git/PHP ``ascii85`` flavour."""

    payload: bytes = bytes(data)
    return base64.a85encode(payload, adobe=False, foldspaces=foldspaces)


def decode_ascii85_adb(data: ByteLike, *, foldspaces: bool = False) -> bytes:
    """Decode ``data`` produced by :func:`encode_ascii85_adb`."""

    payload: bytes = bytes(data)
    return base64.a85decode(
        payload, adobe=False, foldspaces=foldspaces, ignorechars=b"\n\r\t "
    )


def _roundtrip_check() -> bytes:  # pragma: no cover - smoke helper, not part of API
    """Internal smoke check that round-trips a small payload."""

    sample: bytes = b"hello world"
    encoded: bytes = encode_ascii85(sample)
    recovered: bytes = decode_ascii85(encoded)
    assert recovered == sample
    return b"".join(struct.pack(">I", len(encoded))) + encoded
