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
from . import boom

__version__ = "2026.8.1-beta1-pr2"
__license__ = "MIT"
__copyright__ = "Copyright (c) 2026-present aiwonderland"
__author__ = "aiwonderland quantbit@126.com"


def _get_pre(ver: str) -> bool:
    return "pre" in ver


def _get_beta(ver: str) -> bool:
    return "beta" in ver


PRE = _get_pre(__version__)
BETA = _get_beta(__version__)

del _get_pre, _get_beta

if PRE:
    import warnings

    msg = "This is a pre-release build, and many features may still be under development. Please download the latest official release instead of this pre-release version."
    warnings.warn(msg, DeprecationWarning, stacklevel=2)
    del warnings, msg

if BETA:
    import warnings

    msg = "This is a beta-release build. Please download the latest official release instead of this beta-release version."
    warnings.warn(msg, DeprecationWarning, stacklevel=6)
    del warnings, msg

from typing import Any


def __getattr__(attr: Any) -> Any:
    if attr in ("__release__", "__release_version__"):
        import importlib.metadata

        res = importlib.metadata.version("shredder-encryptor")
        del importlib.metadata
        return res
    if attr == "__authors__":
        return __author__
    raise AttributeError(f"module {__name__!r} has no attribute {attr!r}")


del Any
