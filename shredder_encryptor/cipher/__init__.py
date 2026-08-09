"""
A collection of various encryption algorithms.

The :mod:`shredder_encryptor.cipher` package ships a handful of
ready-to-use algorithms that build on the abstractions in
:mod:`shredder_encryptor.codec` and
:mod:`shredder_encryptor.framework`:

* :class:`~shredder_encryptor.cipher.vigenere.VigenereCipher` -- a
  classical polyalphabetic substitution cipher.
* :class:`~shredder_encryptor.cipher.xor_stream.XorStreamCipher` -- a
  reversible stream cipher built on a SHA-256 counter keystream.
* :class:`~shredder_encryptor.cipher.feistel_like.ToyFeistelCipher` --
  a 16-bit Feistel block cipher with PKCS#7 padding.
* :class:`~shredder_encryptor.cipher.sha256_hash.Sha256Hash` -- a
  one-way digest demonstrating non-decryptable ciphers.

All classes are :class:`shredder_encryptor.framework.BaseCipher`
sub-classes, which means they integrate with the shared testing
helpers and the :class:`shredder_encryptor.framework.Pipeline`
composer.
"""

from __future__ import annotations

from .feistel_like import BLOCK_SIZE, ToyFeistelCipher
from .sha256_hash import Sha256Hash
from .vigenere import VigenereCipher
from .xor_stream import XorStreamCipher

__all__ = [
    "BLOCK_SIZE",
    "Sha256Hash",
    "ToyFeistelCipher",
    "VigenereCipher",
    "XorStreamCipher",
]
