"""Convenience encoding and decoding helpers used across the project.

The :mod:`shredder_encryptor.codec` package gathers the small,
single-purpose modules that the cipher implementations in
:mod:`shredder_encryptor.cipher` (and the example ciphers in
:mod:`shredder_encryptor.example`) rely on:

* :mod:`text`     -- text/bytes conversion, normalisation, chunking.
* :mod:`hexutil`  -- hexadecimal encoding and integer conversion.
* :mod:`b64`      -- standard and URL-safe base64.
* :mod:`padding`  -- PKCS#7 and zero-byte padding for block ciphers.

Importing this package re-exports the most common helpers so call
sites can simply write ``from shredder_encryptor.codec import b64``.
"""

from __future__ import annotations

from . import b64, hexutil, padding, text
from .b64 import (
    b64_to_int,
    decode,
    decode_url,
    encode,
    encode_url,
    int_to_b64,
    is_base64,
)
from .hexutil import (
    from_hex,
    hex_to_int,
    int_to_hex,
    is_hex,
    normalize_hex,
    to_hex,
)
from .padding import (
    is_pkcs7_padded,
    pkcs7_pad,
    pkcs7_unpad,
    required_padding_length,
    zero_pad,
    zero_unpad,
)
from .text import (
    chunk,
    codepoint_distribution,
    from_bytes,
    normalize,
    safe_str,
    to_bytes,
)

__all__ = [
    "b64",
    "b64_to_int",
    "chunk",
    "codepoint_distribution",
    "decode",
    "decode_url",
    "encode",
    "encode_url",
    "from_bytes",
    "from_hex",
    "hex_to_int",
    "hexutil",
    "int_to_b64",
    "int_to_hex",
    "is_base64",
    "is_hex",
    "is_pkcs7_padded",
    "normalize",
    "normalize_hex",
    "padding",
    "pkcs7_pad",
    "pkcs7_unpad",
    "required_padding_length",
    "safe_str",
    "text",
    "to_bytes",
    "to_hex",
    "zero_pad",
    "zero_unpad",
]

