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
* :class:`~shredder_encryptor.cipher.feistel64.FeistelEcbCipher` --
  a 64-bit Feistel block cipher in ECB mode with PKCS#7 padding.
* :class:`~shredder_encryptor.cipher.feistel64.FeistelCbcCipher` --
  the same block cipher in CBC mode with a random IV prepended to
  every cipher text.
* :class:`~shredder_encryptor.cipher.sha256_hash.Sha256Hash` -- a
  one-way digest demonstrating non-decryptable ciphers.

All classes are :class:`shredder_encryptor.framework.BaseCipher`
sub-classes, which means they integrate with the shared testing
helpers and the :class:`shredder_encryptor.framework.Pipeline`
composer.  None of the ciphers rely on third-party packages -- the
whole module uses the Python standard library only.
"""

from __future__ import annotations

from .feistel64 import BLOCK_SIZE, ROUNDS, FeistelCbcCipher, FeistelEcbCipher
from .sha256_hash import Sha256Hash
from .vigenere import VigenereCipher
from .xor_stream import XorStreamCipher

__all__ = [
    "BLOCK_SIZE",
    "FeistelCbcCipher",
    "FeistelEcbCipher",
    "ROUNDS",
    "Sha256Hash",
    "VigenereCipher",
    "XorStreamCipher",
]