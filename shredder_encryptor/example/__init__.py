"""
An Example Encryptor.

Type: Caesar shift encryption

The example exposes both the historical ``SampleEncrypt`` /
``SampleDecrypt`` wrappers and the underlying :class:`CaesarShift`
engine for callers that want the same behaviour without the wrapper
boilerplate.
"""

from .caesar import CaesarShift, shift
from .decrypt import SampleDecrypt
from .encrypt import SampleEncrypt
from .meta import DEFAULT_ALPHABET, LOWER, UPPER, validate_alphabet

NAME = "example-encryptor"
VERSION = 2
DECRYPTABLE = True
NON_DECRYPTABLE = False

__all__ = [
    "CaesarShift",
    "DEFAULT_ALPHABET",
    "LOWER",
    "SampleDecrypt",
    "SampleEncrypt",
    "UPPER",
    "shift",
    "validate_alphabet",
]