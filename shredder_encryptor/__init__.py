"""
Shredder Encryptor

The magical encoder holds a set of extraordinary codes within it.
The first type is decryptable code, which is generally designed for
decryption purposes. The second type is non-decryptable code—once
you encode data with it, there is no way to decrypt it back.
"""

from . import persistence
from . import codec
from . import framework
from . import cipher

__version__ = "2026.8.1-pre3"
__license__ = "MIT"
__copyright__ = "Copyright (c) 2026-present aiwonderland"
__author__ = "aiwonderland quantbit@126.com"

def _get_pre(ver: str) -> bool:
    return "pre" in ver

PRE = _get_pre(__version__)

del _get_pre

if PRE:
    import warnings

    msg = "This is a pre-release build, and many features may still be under development. Please download the latest official release instead of this pre-release version."
    warnings.warn(msg, DeprecationWarning, stacklevel=4)
    del warnings, msg
