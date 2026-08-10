"""
Store keys with persistent storage.
The purpose of this file is to create utilities that make storing keys more convenient.

This module offers a tiny, dependency-free key store used by the rest of
``shredder_encryptor``.  Each "key" is a chunk of opaque bytes (for
example a Fernet key, a raw symmetric key or a wrapped secret)
identified by a short, human-readable ``name``.  Keys live inside a
directory on disk (defaulting to ``~/.shredder_encryptor/keys``) and
are written with strict file permissions so they are not world
readable.

The implementation relies only on the Python standard library so it can
be used on any platform supported by the project, including Windows
where the classic ``0o600`` permission bit is emulated by removing
inherited ACL entries that grant access to other users.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Final, Union

#: Type alias for arguments accepted by the path helpers throughout
#: this module.  ``None`` is treated as "use the default directory".
PathLike = Union[str, os.PathLike[str], Path]

__all__ = [
    "DEFAULT_KEY_DIR",
    "KEY_FILE_SUFFIX",
    "MAX_KEY_NAME_LENGTH",
    "KeyStoreError",
    "default_key_dir",
    "validate_key_name",
    "save_key",
    "load_key",
    "delete_key",
    "list_keys",
    "key_exists",
    "clear_keys",
]


#: Default directory used to persist keys when the caller does not pass one.
DEFAULT_KEY_DIR: Path = Path.home() / ".shredder_encryptor" / "keys"

#: File name suffix used for every key blob on disk.
KEY_FILE_SUFFIX: str = ".key"

#: Maximum allowed length for a key name.  The limit guards against
#: pathologically long names that would be inconvenient on every platform.
MAX_KEY_NAME_LENGTH: int = 128

#: Permission bits applied to every key file.  ``0o600`` means "owner may
#: read and write, nobody else may access".  This is the closest portable
#: equivalent to a private key file.
_KEY_FILE_MODE: Final[int] = 0o600

#: Permission bits applied to the key directory.  ``0o700`` keeps the
#: directory itself private so that key names cannot be listed by other
#: users on the host.
_KEY_DIR_MODE: Final[int] = 0o700

#: Reserved Windows device names that must never be used as file names.
#: ``Path`` happily creates files such as ``CON`` or ``NUL`` on Windows
#: which then fail mysteriously later.  We reject them up front.
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)

#: Strict pattern for valid key names.  Only ASCII letters, digits,
#: ``-``, ``_`` and ``.`` are allowed; leading/trailing dots and dashes
#: are rejected to keep the names safe across platforms.
_KEY_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,%d}$" % (MAX_KEY_NAME_LENGTH - 1)
)


class KeyStoreError(Exception):
    """Raised when a key store operation cannot be completed safely."""


def _coerce_path(path: PathLike | None) -> Path:
    """Return a :class:`Path` for ``path`` or the default key directory."""

    if path is None:
        return DEFAULT_KEY_DIR
    if isinstance(path, Path):
        return path
    return Path(os.fspath(path))


def _ensure_directory(directory: Path) -> None:
    """Create ``directory`` (and parents) using private permissions."""

    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise KeyStoreError(
            f"unable to create key directory {directory!s}: {exc}"
        ) from exc

    if os.name == "posix":
        try:
            os.chmod(directory, _KEY_DIR_MODE)
        except OSError as exc:
            raise KeyStoreError(
                f"unable to restrict directory permissions on {directory!s}: {exc}"
            ) from exc
    else:
        _tighten_windows_permissions(directory, kind="directory")


def _tighten_windows_permissions(target: Path, *, kind: str) -> None:
    """Best-effort equivalent of ``chmod 0o700``/``0o600`` on Windows.

    The function only strips inherited ACL entries that grant access to
    identities other than the current user.  It never adds new
    permissions so it will not widen access on shared systems.  The
    operation is wrapped in ``KeyStoreError`` so callers can surface a
    consistent error type.

    Parameters
    ----------
    target:
        File or directory whose ACL should be tightened.
    kind:
        Either ``"directory"`` or ``"file"``.  The label is included
        in the error message so the caller can tell which side of the
        save path failed.
    """

    if os.name != "nt":
        return
    try:
        import subprocess
    except ImportError:  # pragma: no cover - subprocess is always importable
        return
    script = (
        "$acl = Get-Acl -LiteralPath '%s';"
        "$identities = $acl.Access |"
        " Where-Object { $_.IdentityReference -ne [System.Security.Principal.NTAccount]'%s' };"
        "foreach ($entry in $identities) { $acl.RemoveAccessRule($entry) | Out-Null; }"
        "$acl | Set-Acl -LiteralPath '%s'"
    ) % (
        str(target).replace("'", "''"),
        os.environ.get("USERNAME", ""),
        str(target).replace("'", "''"),
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            check=False,
            capture_output=True,
            text=True,
        )
    except (OSError, FileNotFoundError) as exc:
        raise KeyStoreError(
            f"unable to tighten {kind} permissions on {target!s}: {exc}"
        ) from exc
    if completed.returncode != 0:
        raise KeyStoreError(
            f"unable to tighten {kind} permissions on {target!s}: "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )


def _resolve_key_path(name: str, directory: Path) -> Path:
    """Return the path used to persist the key identified by ``name``."""

    return directory / f"{name}{KEY_FILE_SUFFIX}"


def validate_key_name(name: str) -> str:
    """Return ``name`` unchanged when it is a legal key identifier.

    ``KeyStoreError`` is raised for anything that is not safe to embed
    in a file name on the supported platforms.  The validation rules
    are intentionally conservative: callers that need free-form names
    should hash them before calling this module.
    """

    if not isinstance(name, str):
        raise KeyStoreError("key name must be a string")
    if not name:
        raise KeyStoreError("key name must not be empty")
    if len(name) > MAX_KEY_NAME_LENGTH:
        raise KeyStoreError(
            f"key name must be at most {MAX_KEY_NAME_LENGTH} characters"
        )
    if not _KEY_NAME_PATTERN.match(name):
        raise KeyStoreError(
            "key name may only contain ASCII letters, digits, '_', '-' or '.',"
            " and must start with a letter or digit"
        )
    upper = name.upper()
    if upper in _WINDOWS_RESERVED_NAMES:
        raise KeyStoreError(f"key name {name!r} is a reserved Windows device name")
    if name in {".", ".."}:
        raise KeyStoreError("key name may not be '.' or '..'")
    return name


def default_key_dir() -> Path:
    """Return the default key directory, creating it if necessary."""

    directory = DEFAULT_KEY_DIR
    _ensure_directory(directory)
    return directory


def save_key(
    name: str,
    data: bytes | bytearray | memoryview,
    path: PathLike | None = None,
    *,
    overwrite: bool = False,
) -> Path:
    """Persist ``data`` under ``name`` and return the resulting file path.

    The write is atomic: the payload is first written to a temporary
    file inside the destination directory and only then renamed into
    place.  This avoids leaving a half-written key behind if the process
    is interrupted mid-write.

    Parameters
    ----------
    name:
        Identifier for the key.  See :func:`validate_key_name` for the
        accepted character set.
    data:
        Raw bytes to store.  ``bytearray`` and ``memoryview`` inputs are
        accepted and copied so later mutations of the caller data do not
        affect the persisted file.
    path:
        Optional directory override.  When omitted the
        :data:`DEFAULT_KEY_DIR` is used.
    overwrite:
        When ``True`` an existing key is replaced.  The default is
        ``False`` to make accidental clobbering less likely.
    """

    validate_key_name(name)

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise KeyStoreError("key data must be bytes-like")
    payload = bytes(data)
    if not payload:
        raise KeyStoreError("key data must not be empty")

    directory = _coerce_path(path)
    _ensure_directory(directory)

    destination = _resolve_key_path(name, directory)
    if destination.exists() and not overwrite:
        raise KeyStoreError(f"key {name!r} already exists in {directory!s}")

    # ``mkstemp`` returns a low-level file descriptor we own.  The
    # unique name keeps concurrent writers from clobbering one another
    # inside the same directory.
    fd, tmp_path_str = tempfile.mkstemp(
        prefix=f".{name}.",
        suffix=f"{KEY_FILE_SUFFIX}.tmp",
        dir=str(directory),
    )
    tmp_path = Path(tmp_path_str)
    try:
        try:
            with os.fdopen(fd, "wb") as tmp_file:
                tmp_file.write(payload)
                tmp_file.flush()
                try:
                    os.fsync(tmp_file.fileno())
                except OSError as exc:
                    # ``fsync`` may fail on some filesystems (notably
                    # certain network mounts).  Surface a consistent
                    # error so the cleanup path below still fires.
                    raise KeyStoreError(
                        f"unable to flush key payload to disk: {exc}"
                    ) from exc
        except OSError as exc:
            raise KeyStoreError(f"unable to write key payload: {exc}") from exc
        if os.name == "posix":
            try:
                os.chmod(tmp_path, _KEY_FILE_MODE)
            except OSError as exc:
                raise KeyStoreError(
                    f"unable to restrict file permissions on {tmp_path!s}: {exc}"
                ) from exc
        os.replace(tmp_path, destination)
        if os.name != "posix":
            _tighten_windows_permissions(destination, kind="file")
    except BaseException:
        # Best effort cleanup so we never leave temporary files behind.
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return destination


def load_key(name: str, path: PathLike | None = None) -> bytes:
    """Return the raw bytes previously stored under ``name``."""

    validate_key_name(name)
    directory = _coerce_path(path)
    key_path = _resolve_key_path(name, directory)
    try:
        with open(key_path, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError as exc:
        raise KeyStoreError(f"key {name!r} not found in {directory!s}") from exc
    except OSError as exc:
        raise KeyStoreError(f"unable to read key {name!r}: {exc}") from exc


def delete_key(
    name: str,
    path: PathLike | None = None,
    *,
    missing_ok: bool = False,
) -> bool:
    """Remove ``name`` from the store.  Return ``True`` when a file was deleted.

    The default behaviour mirrors :func:`os.remove`: missing keys raise
    ``KeyStoreError``.  Pass ``missing_ok=True`` to silently ignore
    missing entries, which is convenient for idempotent cleanup
    routines.
    """

    validate_key_name(name)
    directory = _coerce_path(path)
    key_path = _resolve_key_path(name, directory)
    try:
        key_path.unlink()
        return True
    except FileNotFoundError:
        if missing_ok:
            return False
        raise KeyStoreError(f"key {name!r} not found in {directory!s}") from None
    except OSError as exc:
        raise KeyStoreError(f"unable to delete key {name!r}: {exc}") from exc


def list_keys(path: PathLike | None = None, *, cleanup: bool = False) -> list[str]:
    """Return a sorted list of key names currently stored on disk.

    When ``cleanup`` is ``True`` any leftover temporary file produced
    by an interrupted :func:`save_key` is removed before the listing
    is built.  The temporary files are recognised by their
    ``.tmp`` suffix and are matched against known key names so
    un-related stray files are never touched.
    """

    directory = _coerce_path(path)
    if not directory.exists():
        return []
    if not directory.is_dir():
        raise KeyStoreError(f"key path {directory!s} is not a directory")

    known_names: set[str] = set()
    names: list[str] = []
    try:
        entries: list[Path] = list(directory.iterdir())
    except OSError as exc:
        raise KeyStoreError(
            f"unable to list keys in {directory!s}: {exc}"
        ) from exc
    # First pass: collect the known key names so the second pass can
    # decide which ``.tmp`` files belong to a real key.  Splitting the
    # work into two iterations makes the cleanup step robust against
    # directory entry orderings (the ``.tmp`` files are usually listed
    # before the corresponding ``.key`` on Windows).
    for entry in entries:
        if not entry.is_file():
            continue
        if entry.name.endswith(KEY_FILE_SUFFIX):
            candidate = entry.name[: -len(KEY_FILE_SUFFIX)]
            try:
                validate_key_name(candidate)
            except KeyStoreError:
                continue
            known_names.add(candidate)
            names.append(candidate)
    if cleanup:
        for entry in entries:
            if not entry.is_file():
                continue
            if not entry.name.endswith(f"{KEY_FILE_SUFFIX}.tmp"):
                continue
            stem = entry.name[: -len(f"{KEY_FILE_SUFFIX}.tmp")]
            # ``tempfile.mkstemp`` builds names like
            # ``.primary.xyz123.key.tmp``.  The original key name is the
            # chunk between the leading dot and the random suffix; we
            # only remove the file when that chunk still maps to a
            # known key, which is enough to make the operation safe on
            # user-managed directories.
            if stem.startswith(".") and stem[1:].split(".", 1)[0] in known_names:
                try:
                    entry.unlink()
                except OSError:
                    # Listing must not fail because of a stray temporary
                    # file we cannot delete (locked, permission, ...).
                    pass
    names.sort()
    return names


def key_exists(name: str, path: PathLike | None = None) -> bool:
    """Return ``True`` if a key named ``name`` is present in the store."""

    validate_key_name(name)
    directory = _coerce_path(path)
    return _resolve_key_path(name, directory).exists()


def clear_keys(path: PathLike | None = None) -> int:
    """Delete every key in ``path`` and return the number of removed files.

    When ``path`` is omitted the default key directory is used.  Missing
    directories are treated as already-empty stores and report ``0``.
    """

    directory = _coerce_path(path)
    if not directory.exists():
        return 0
    removed = 0
    for name in list_keys(directory):
        if delete_key(name, directory, missing_ok=True):
            removed += 1
    return removed


def _reset_default_directory_for_tests() -> None:  # pragma: no cover - test helper
    """Test helper that forces a fresh default directory on every call.

    The function is intentionally not exported through ``__all__``; it
    is used by the unit tests to guarantee isolation between runs that
    share the same process.  It is also a no-op when the default
    directory does not exist yet.
    """

    directory = DEFAULT_KEY_DIR
    if directory.exists():
        shutil.rmtree(directory, ignore_errors=True)


# ``_reset_default_directory_for_tests`` below exposes a hook used by
# the unit tests to keep the default directory isolated.  It is not
# part of the public API.
