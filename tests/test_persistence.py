"""Tests for :mod:`shredder_encryptor.persistence`."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from shredder_encryptor.persistence import (
    KEY_FILE_SUFFIX,
    MAX_KEY_NAME_LENGTH,
    KeyStoreError,
    clear_keys,
    delete_key,
    key_exists,
    list_keys,
    load_key,
    save_key,
    validate_key_name,
)


# ---------------------------------------------------------------------------
# validate_key_name
# ---------------------------------------------------------------------------
class TestValidateKeyName:
    @pytest.mark.parametrize(
        "name",
        ["a", "A1", "session-1", "wrap.v2", "key_42"],
    )
    def test_accepts_simple_names(self, name):
        assert validate_key_name(name) == name

    def test_rejects_empty(self):
        with pytest.raises(KeyStoreError):
            validate_key_name("")

    @pytest.mark.parametrize("value", [None, 1, b"abc", object()])
    def test_rejects_non_string(self, value):
        with pytest.raises(KeyStoreError):
            validate_key_name(value)  # type: ignore[arg-type]

    @pytest.mark.parametrize("bad", [".", "..", "../escape", "a/b", "a\\b", "a b"])
    def test_rejects_traversal(self, bad):
        with pytest.raises(KeyStoreError):
            validate_key_name(bad)

    @pytest.mark.parametrize("reserved", ["CON", "con", "Com1", "LPT9", "NUL"])
    def test_rejects_reserved_windows_names(self, reserved):
        with pytest.raises(KeyStoreError):
            validate_key_name(reserved)

    def test_rejects_oversized_name(self):
        with pytest.raises(KeyStoreError):
            validate_key_name("a" * (MAX_KEY_NAME_LENGTH + 1))

    def test_accepts_max_length(self):
        boundary = "a" * MAX_KEY_NAME_LENGTH
        assert validate_key_name(boundary) == boundary


# ---------------------------------------------------------------------------
# save / load
# ---------------------------------------------------------------------------
class TestSaveLoad:
    def test_save_and_load_round_trip(self, tmp_path: Path):
        store = tmp_path / "keys"
        payload = b"super-secret-bytes"
        path = save_key("primary", payload, store)
        assert path.is_file()
        assert path == store / f"primary{KEY_FILE_SUFFIX}"
        assert load_key("primary", store) == payload

    def test_accepts_bytearray_and_memoryview(self, tmp_path: Path):
        store = tmp_path / "keys"
        save_key("buf", bytearray(b"mutable"), store)
        assert load_key("buf", store) == b"mutable"
        save_key("mem", memoryview(b"view"), store)
        assert load_key("mem", store) == b"view"

    def test_save_rejects_empty_data(self, tmp_path: Path):
        with pytest.raises(KeyStoreError):
            save_key("empty", b"", tmp_path / "keys")

    def test_save_rejects_non_bytes(self, tmp_path: Path):
        with pytest.raises(KeyStoreError):
            save_key("text", "not-bytes", tmp_path / "keys")  # type: ignore[arg-type]

    def test_save_rejects_invalid_name(self, tmp_path: Path):
        with pytest.raises(KeyStoreError):
            save_key("../escape", b"x", tmp_path / "keys")

    def test_save_refuses_to_overwrite_by_default(self, tmp_path: Path):
        store = tmp_path / "keys"
        save_key("dup", b"one", store)
        with pytest.raises(KeyStoreError):
            save_key("dup", b"two", store)
        assert load_key("dup", store) == b"one"

    def test_overwrite_replaces_data(self, tmp_path: Path):
        store = tmp_path / "keys"
        save_key("dup", b"one", store)
        save_key("dup", b"two", store, overwrite=True)
        assert load_key("dup", store) == b"two"

    def test_save_creates_missing_directory(self, tmp_path: Path):
        nested = tmp_path / "deep" / "nest"
        save_key("auto", b"x", nested)
        assert nested.is_dir()
        assert load_key("auto", nested) == b"x"

    def test_path_argument_accepts_string(self, tmp_path: Path):
        save_key("str-path", b"x", str(tmp_path / "keys"))
        assert (tmp_path / "keys" / f"str-path{KEY_FILE_SUFFIX}").is_file()


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------
@pytest.mark.skipif(os.name != "posix", reason="POSIX-only permission check")
class TestPosixPermissions:
    def test_file_permissions_are_owner_only(self, tmp_path: Path):
        store = tmp_path / "keys"
        path = save_key("perm", b"x", store)
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600

    def test_directory_permissions_are_owner_only(self, tmp_path: Path):
        store = tmp_path / "keys"
        save_key("perm", b"x", store)
        mode = stat.S_IMODE(store.stat().st_mode)
        assert mode == 0o700


def test_no_world_readable_key_files(tmp_path: Path):
    store = tmp_path / "keys"
    save_key("k1", b"one", store)
    save_key("k2", b"two", store)
    if os.name == "posix":
        for entry in store.iterdir():
            mode = stat.S_IMODE(entry.stat().st_mode)
            assert mode == 0o600, msg == str(entry)


# ---------------------------------------------------------------------------
# Delete / listing / existence
# ---------------------------------------------------------------------------
class TestDeleteAndListing:
    def _setup(self, store: Path) -> None:
        save_key("alpha", b"1", store)
        save_key("beta", b"22", store)
        save_key("gamma", b"333", store)

    def test_list_keys_is_sorted_and_skips_unknown(self, tmp_path: Path):
        store = tmp_path / "keys"
        self._setup(store)
        (store / "README.md").write_text("hi", encoding="utf-8")
        assert list_keys(store) == ["alpha", "beta", "gamma"]

    def test_key_exists(self, tmp_path: Path):
        store = tmp_path / "keys"
        self._setup(store)
        assert key_exists("alpha", store)
        assert not key_exists("missing", store)

    def test_delete_key_returns_true_and_removes(self, tmp_path: Path):
        store = tmp_path / "keys"
        self._setup(store)
        assert delete_key("beta", store)
        assert list_keys(store) == ["alpha", "gamma"]

    def test_delete_missing_raises(self, tmp_path: Path):
        with pytest.raises(KeyStoreError):
            delete_key("ghost", tmp_path / "keys")

    def test_delete_missing_with_missing_ok(self, tmp_path: Path):
        assert not delete_key("ghost", tmp_path / "keys", missing_ok=True)

    def test_load_missing_raises(self, tmp_path: Path):
        with pytest.raises(KeyStoreError):
            load_key("ghost", tmp_path / "keys")

    def test_clear_keys(self, tmp_path: Path):
        store = tmp_path / "keys"
        self._setup(store)
        removed = clear_keys(store)
        assert removed == 3
        assert list_keys(store) == []
        assert clear_keys(store) == 0

    def test_list_keys_on_missing_directory_is_empty(self, tmp_path: Path):
        missing = tmp_path / "absent"
        assert list_keys(missing) == []
        assert clear_keys(missing) == 0


# ---------------------------------------------------------------------------
# cleanup=True behaviour
# ---------------------------------------------------------------------------
class TestCleanupTempFiles:
    def test_cleanup_removes_known_tmp_files(self, tmp_path: Path):
        store = tmp_path / "keys"
        save_key("alpha", b"x", store)
        (store / ".alpha.deadbeef.key.tmp").write_bytes(b"partial")
        (store / ".ghost.deadbeef.key.tmp").write_bytes(b"partial")
        names = list_keys(store, cleanup=True)
        assert names == ["alpha"]
        remaining = {p.name for p in store.iterdir()}
        assert ".alpha.deadbeef.key.tmp" not in remaining
        assert ".ghost.deadbeef.key.tmp" in remaining

    def test_cleanup_default_is_off(self, tmp_path: Path):
        store = tmp_path / "keys"
        save_key("alpha", b"x", store)
        (store / ".alpha.deadbeef.key.tmp").write_bytes(b"partial")
        list_keys(store)
        assert ".alpha.deadbeef.key.tmp" in {p.name for p in store.iterdir()}
