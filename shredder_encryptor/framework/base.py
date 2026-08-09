"""Building blocks for implementing ciphers in a uniform way.

The :mod:`shredder_encryptor.framework` package provides the small set
of abstractions that the cipher implementations in
:mod:`shredder_encryptor.cipher` (and the example ciphers) share.  A
new cipher only has to subclass :class:`BaseCipher` and implement
:meth:`encrypt` (and, when reversible, :meth:`decrypt`); the base
class takes care of validation, equality, repr and the
``DECRYPTABLE``/``NON_DECRYPTABLE`` flags.

The module is intentionally pure-stdlib so that importing the
framework does not pull any extra dependencies.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Mapping, Protocol, runtime_checkable

__all__ = [
    "CipherError",
    "Cipher",
    "BlockCipher",
    "StreamCipher",
    "HashBasedCipher",
    "BaseCipher",
]


class CipherError(Exception):
    """Raised when a cipher operation cannot be performed safely."""


@runtime_checkable
class Cipher(Protocol):
    """Protocol every concrete cipher implementation satisfies."""

    algorithm: ClassVar[str]

    def encrypt(self, plaintext: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes) -> bytes: ...


@runtime_checkable
class BlockCipher(Cipher, Protocol):
    """Protocol for block ciphers that operate on fixed-size chunks."""

    block_size: ClassVar[int]

    def encrypt_block(self, block: bytes) -> bytes: ...

    def decrypt_block(self, block: bytes) -> bytes: ...


@runtime_checkable
class StreamCipher(Cipher, Protocol):
    """Protocol for stream ciphers that produce a keystream."""

    def generate_keystream(self, length: int) -> bytes: ...


@runtime_checkable
class HashBasedCipher(Cipher, Protocol):
    """Protocol for non-reversible ciphers (hashes)."""

    digest_size: ClassVar[int]

    def verify(self, plaintext: bytes, digest: bytes) -> bool: ...


class BaseCipher(ABC):
    """Abstract base class that wires together validation and metadata."""

    #: Identifier of the algorithm (for example ``"caesar"``).  Must
    #: be overridden by sub-classes.
    algorithm: ClassVar[str] = ""

    #: Whether the cipher supports :meth:`decrypt`.  Defaults to
    #: ``True``; one-way ciphers must set it to ``False``.
    DECRYPTABLE: ClassVar[bool] = True

    #: Default parameter values used by :meth:`__init__` to build the
    #: dictionary that drives equality and ``repr``.
    parameters: ClassVar[Mapping[str, Any]] = {}

    def __init__(self, **kwargs: Any) -> None:
        merged: dict[str, Any] = dict(self.parameters)
        merged.update(kwargs)
        self._params: dict[str, Any] = merged

    @property
    def name(self) -> str:
        """Return ``"<Class>:<algorithm>"``."""

        algo: str = self.algorithm or type(self).__name__
        return f"{type(self).__name__}:{algo}"

    def describe(self) -> dict[str, Any]:
        """Return a JSON-friendly description of the cipher."""

        return {
            "name": self.name,
            "algorithm": self.algorithm,
            "decryptable": self.DECRYPTABLE,
            "parameters": dict(self._params),
        }

    @staticmethod
    def _require_bytes(data: Any, name: str) -> bytes:
        """Return ``data`` as ``bytes`` or raise :class:`CipherError`."""

        if isinstance(data, (bytes, bytearray, memoryview)):
            return bytes(data)
        raise CipherError(
            f"{name} must be bytes-like, got {type(data).__name__}"
        )

    @staticmethod
    def _require_block(data: bytes, block_size: int, name: str) -> bytes:
        """Return ``data`` when it matches ``block_size``."""

        if block_size <= 0:
            raise CipherError("block_size must be positive")
        if len(data) != block_size:
            raise CipherError(
                f"{name} must be exactly {block_size} bytes, got {len(data)}"
            )
        return data

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and return the cipher text."""

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ``ciphertext`` and return the original plaintext.

        The default implementation raises :class:`CipherError` when
        :attr:`DECRYPTABLE` is ``False``; reversible ciphers should
        override it.
        """

        if not self.DECRYPTABLE:
            raise CipherError(f"{self.name} does not support decryption")
        raise NotImplementedError(
            f"{type(self).__name__} must implement decrypt()"
        )

    def verify(self, plaintext: bytes, digest: bytes) -> bool:
        """Return ``True`` when ``digest`` matches ``encrypt(plaintext)``."""

        clean_plain: bytes = self._require_bytes(plaintext, "plaintext")
        clean_digest: bytes = self._require_bytes(digest, "digest")
        return self.encrypt(clean_plain) == clean_digest

    def __repr__(self) -> str:
        params: str = ", ".join(
            f"{key}={value!r}" for key, value in self._params.items()
        )
        if params:
            return f"{type(self).__name__}({params})"
        return f"{type(self).__name__}()"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseCipher):
            return NotImplemented
        return type(other) is type(self) and self._params == other._params

    def __hash__(self) -> int:
        return hash((type(self), tuple(sorted(self._params.items()))))
