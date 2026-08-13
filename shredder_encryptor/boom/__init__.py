"""Irreversible (one-way) encryption primitives.

The :mod:`shredder_encryptor.boom` package collects the example
ciphers that demonstrate how the project handles **non-decryptable**
encoding.  The top-level :mod:`shredder_encryptor` package documents
the design as:

***The first type is decryptable code, which is generally designed
for decryption purposes. The second type is non-decryptable
code—once you encode data with it, there is no way to decrypt
it back.***

The :mod:`shredder_encryptor.cipher` package fulfils the first half
of that contract; the :mod:`boom` package fulfils the second half.
Every cipher shipped here subclasses
:class:`shredder_encryptor.framework.BaseCipher` and sets
``DECRYPTABLE = False`` so the shared
:func:`shredder_encryptor.framework.assert_irreversible` helper can
be used to assert the contract.

The package exposes:

* :class:`~shredder_encryptor.boom.truncate.TruncateCipher` -- a
  length-reducing one-way cipher that keeps only a prefix or suffix
  of the input.
* :class:`~shredder_encryptor.boom.discard.DiscardCipher` -- a
  stride-based downsampler that drops every ``N``-th byte.
* :class:`~shredder_encryptor.boom.scramble.ScrambleCipher` -- a
  keyed Fisher–Yates shuffle that consumes its key state so the
  inverse permutation cannot be reconstructed.
* :class:`~shredder_encryptor.boom.bloom.BloomFingerprint` -- a
  Bloom-filter style fingerprint that produces a fixed-size bit
  array (a non-decryptable byte string).

All classes build on the standard library only and avoid the
reversible helpers of :mod:`shredder_encryptor.cipher` so the
boundary between the two halves of the API stays clear.

.. note::

    The ciphers in this package are pedagogical.  The cryptographic
    strength of :class:`ScrambleCipher` and the bit distribution of
    :class:`BloomFingerprint` are intentionally simpler than what a
    production system would require; treat them as a teaching aid,
    not as production-grade primitives.
"""

from __future__ import annotations

from . import bloom, discard, scramble, truncate
from .bloom import (
    DEFAULT_HASHES,
    DEFAULT_SIZE,
    BloomFingerprint,
)
from .discard import DEFAULT_STEP, DiscardCipher
from .scramble import ScrambleCipher
from .truncate import KEEP_HEAD, KEEP_TAIL, TruncateCipher

__all__ = [
    "DEFAULT_HASHES",
    "DEFAULT_SIZE",
    "DEFAULT_STEP",
    "BloomFingerprint",
    "DiscardCipher",
    "KEEP_HEAD",
    "KEEP_TAIL",
    "ScrambleCipher",
    "TruncateCipher",
    "bloom",
    "discard",
    "scramble",
    "truncate",
]
