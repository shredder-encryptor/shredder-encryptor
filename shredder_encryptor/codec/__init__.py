"""Convenience encoding and decoding helpers used across the project.

The :mod:`shredder_encryptor.codec` package gathers the small,
single-purpose modules that the cipher implementations in
:mod:`shredder_encryptor.cipher` (and the example ciphers in
:mod:`shredder_encryptor.example`) rely on:

* :mod:`text`            -- text/bytes conversion, normalisation, chunking.
* :mod:`hexutil`         -- hexadecimal encoding and integer conversion.
* :mod:`b64`             -- standard and URL-safe base64.
* :mod:`padding`         -- PKCS#7 and zero-byte padding for block ciphers.
* :mod:`digest`          -- thin wrapper around :mod:`hashlib` digests.
* :mod:`token`           -- cryptographically secure tokens and helpers.
* :mod:`url`             -- URL percent-encoding and form helpers.
* :mod:`quoted_printable`-- RFC 2045 quoted-printable encoding.
* :mod:`uuencode`        -- historic UUencode encoding.
* :mod:`ascii85`         -- ASCII85 / Base85 variants.

Importing this package re-exports the most common helpers so call
sites can simply write ``from shredder_encryptor.codec import b64``.
"""

from __future__ import annotations

from . import (
    ascii85,
    b64,
    digest,
    hexutil,
    padding,
    quoted_printable,
    text,
    token,
    url,
    uuencode,
)
from .ascii85 import (
    decode_ascii85,
    decode_ascii85_adb,
    encode_ascii85,
    encode_ascii85_adb,
)
from .b64 import (
    b64_to_int,
    decode,
    decode_url,
    encode,
    encode_url,
    int_to_b64,
    is_base64,
)
from .digest import (
    algorithms_with_variable_size,
    digest as digest_bytes,
    hexdigest,
    new_hasher,
    supported_algorithms,
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
from .quoted_printable import decode_qp, encode_qp
from .text import (
    chunk,
    codepoint_distribution,
    from_bytes,
    normalize,
    safe_str,
    to_bytes,
)
from .token import (
    constant_time_eq,
    new_token,
    token_bytes,
    token_hex,
    token_urlsafe,
)
from .url import quote, unquote, urldecode, urlencode
from .uuencode import uudecode, uuencode

__all__ = [
    "ascii85",
    "b64",
    "b64_to_int",
    "chunk",
    "codepoint_distribution",
    "constant_time_eq",
    "decode",
    "decode_ascii85",
    "decode_ascii85_adb",
    "decode_qp",
    "decode_url",
    "digest",
    "digest_bytes",
    "encode",
    "encode_ascii85",
    "encode_ascii85_adb",
    "encode_qp",
    "encode_url",
    "from_bytes",
    "from_hex",
    "hex_to_int",
    "hexdigest",
    "hexutil",
    "int_to_b64",
    "int_to_hex",
    "is_base64",
    "is_hex",
    "is_pkcs7_padded",
    "new_hasher",
    "new_token",
    "normalize",
    "normalize_hex",
    "padding",
    "pkcs7_pad",
    "pkcs7_unpad",
    "quote",
    "quoted_printable",
    "required_padding_length",
    "safe_str",
    "supported_algorithms",
    "algorithms_with_variable_size",
    "text",
    "to_bytes",
    "to_hex",
    "token",
    "token_bytes",
    "token_hex",
    "token_urlsafe",
    "unquote",
    "urldecode",
    "urlencode",
    "uudecode",
    "uuencode",
    "url",
    "zero_pad",
    "zero_unpad",
]
