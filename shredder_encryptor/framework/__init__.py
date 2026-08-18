"""Reusable building blocks for authoring new ciphers.

The :mod:`shredder_encryptor.framework` package bundles the small
abstractions that every cipher implementation in the project should
share:

* :mod:`base`     -- :class:`BaseCipher`, the :class:`Cipher` /
  :class:`BlockCipher` / :class:`StreamCipher` / :class:`HashBasedCipher`
  protocols and the shared :class:`CipherError`.
* :mod:`pipeline` -- :class:`Pipeline` and the module level
  :func:`encrypt` / :func:`decrypt` helpers.
* :mod:`testing`  -- :func:`assert_round_trip`,
  :func:`assert_irreversible`, :func:`fuzz_cipher` and
  :func:`random_bytes`.

Importing the package re-exports the most useful symbols so that
new cipher modules can simply do::

    from shredder_encryptor.framework import BaseCipher
"""

from __future__ import annotations

from . import base, pipeline, testing
from .base import (
    BaseCipher,
    BlockCipher,
    Cipher,
    CipherError,
    HashBasedCipher,
    StreamCipher,
)
from .pipeline import Pipeline, decrypt, encrypt
from .testing import (
    assert_irreversible,
    assert_round_trip,
    fuzz_cipher,
    random_bytes,
)

__all__ = [
    "BaseCipher",
    "BlockCipher",
    "Cipher",
    "CipherError",
    "HashBasedCipher",
    "Pipeline",
    "StreamCipher",
    "assert_irreversible",
    "assert_round_trip",
    # "base",
    "decrypt",
    "encrypt",
    "fuzz_cipher",
    # "pipeline",
    "random_bytes",
    # "testing",
]
