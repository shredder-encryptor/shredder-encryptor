"""Message digests backed by :mod:`hashlib`.

The module exposes a small, uniform surface around ``hashlib`` so the
rest of the project does not have to remember the spelling of every
algorithm or which digest sizes are variable (``shake_*``).

Typical use::

    from shredder_encryptor.codec.digest import digest, hexdigest

    digest(b"hello")               # 32-byte SHA-256 bytes
    hexdigest(b"hello", "sha1")    # "aaf4c61d..."
"""

from __future__ import annotations

import hashlib
from typing import Final

from .text import ByteLike

__all__ = [
    "DEFAULT_ALGORITHM",
    "digest",
    "hexdigest",
    "supported_algorithms",
    "algorithms_with_variable_size",
    "new_hasher",
]


#: Default digest algorithm used when callers do not pick one.  SHA-256
#: is what most callers want; it is collision resistant for practical
#: purposes and supported on every Python build.
DEFAULT_ALGORITHM: Final[str] = "sha256"

#: Algorithms whose digest length depends on the caller rather than on
#: a fixed property of the function.  ``digest()`` and ``hexdigest()``
#: require ``length`` for those algorithms.
_VARIABLE_SIZE_ALGOS: Final[frozenset[str]] = frozenset({"shake_128", "shake_256"})


def supported_algorithms() -> list[str]:
    """Return a sorted list of guaranteed digest algorithm names."""

    return sorted(hashlib.algorithms_guaranteed)


def algorithms_with_variable_size() -> list[str]:
    """Return the sorted list of algorithms that need ``length``."""

    return sorted(_VARIABLE_SIZE_ALGOS)


def new_hasher(algorithm: str = DEFAULT_ALGORITHM):
    """Return a fresh :func:`hashlib.new` instance for ``algorithm``."""

    if not isinstance(algorithm, str) or not algorithm:
        raise TypeError("algorithm must be a non-empty string")
    try:
        return hashlib.new(algorithm)
    except (KeyError, ValueError) as exc:
        raise ValueError(f"unsupported digest algorithm: {algorithm!r}") from exc


def digest(
    data: ByteLike,
    algorithm: str = DEFAULT_ALGORITHM,
    *,
    length: int | None = None,
) -> bytes:
    """Return the digest of ``data`` using ``algorithm``.

    ``length`` is required when ``algorithm`` is in
    :data:`_VARIABLE_SIZE_ALGOS` (``shake_128`` / ``shake_256``) and
    ignored otherwise.  Negative lengths raise :class:`ValueError`.
    """

    if algorithm in _VARIABLE_SIZE_ALGOS:
        if length is None:
            raise ValueError(
                f"{algorithm} requires an explicit length (use "
                f"length=...)"
            )
        if length < 0:
            raise ValueError("length must be non-negative")
        hasher = hashlib.new(algorithm)
        hasher.update(bytes(data))
        return hasher.digest(length)
    hasher = new_hasher(algorithm)
    hasher.update(bytes(data))
    return hasher.digest()


def hexdigest(
    data: ByteLike,
    algorithm: str = DEFAULT_ALGORITHM,
    *,
    length: int | None = None,
) -> str:
    """Return the digest of ``data`` formatted as lower-case hex."""

    return digest(data, algorithm, length=length).hex()