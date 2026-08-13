"""Tests for :mod:`shredder_encryptor.boom`.

The :mod:`shredder_encryptor.boom` package ships irreversible
encryption primitives.  All ciphers in the package set
``DECRYPTABLE = False`` so the shared
:func:`shredder_encryptor.framework.assert_irreversible` helper can
be used to verify the contract.
"""

from __future__ import annotations

import os
from collections import Counter

import pytest

from shredder_encryptor.boom import (
    DEFAULT_HASHES,
    DEFAULT_SIZE,
    DEFAULT_STEP,
    BloomFingerprint,
    DiscardCipher,
    KEEP_HEAD,
    KEEP_TAIL,
    ScrambleCipher,
    TruncateCipher,
    bloom,
    discard,
    scramble,
    truncate,
)
from shredder_encryptor.framework import (
    BaseCipher,
    CipherError,
    Pipeline,
    assert_irreversible,
)


# ---------------------------------------------------------------------------
# Package-level smoke
# ---------------------------------------------------------------------------
class TestBoomPackage:
    def test_top_level_reexports(self) -> None:
        from shredder_encryptor import boom as top_boom

        assert top_boom.TruncateCipher is TruncateCipher
        assert top_boom.DiscardCipher is DiscardCipher
        assert top_boom.ScrambleCipher is ScrambleCipher
        assert top_boom.BloomFingerprint is BloomFingerprint

    def test_submodules_are_exported(self) -> None:
        assert callable(truncate.TruncateCipher)
        assert callable(discard.DiscardCipher)
        assert callable(scramble.ScrambleCipher)
        assert callable(bloom.BloomFingerprint)

    def test_all_shipped_classes_are_one_way(self) -> None:
        for cipher_cls in (
            TruncateCipher,
            DiscardCipher,
            ScrambleCipher,
            BloomFingerprint,
        ):
            assert issubclass(cipher_cls, BaseCipher)
            assert cipher_cls.DECRYPTABLE is False

    def test_default_digest_lengths(self) -> None:
        assert BloomFingerprint.digest_size == DEFAULT_SIZE
        assert DEFAULT_SIZE > 0
        assert DEFAULT_HASHES > 0
        assert DEFAULT_STEP > 0


# ---------------------------------------------------------------------------
# TruncateCipher
# ---------------------------------------------------------------------------
class TestTruncateCipher:
    def test_head_keeps_prefix(self) -> None:
        cipher = TruncateCipher(keep=3)
        assert cipher.encrypt(b"abcdef") == b"abc"

    def test_tail_keeps_suffix(self) -> None:
        cipher = TruncateCipher(keep=3, side=KEEP_TAIL)
        assert cipher.encrypt(b"abcdef") == b"def"

    def test_short_input_returned_unchanged(self) -> None:
        cipher = TruncateCipher(keep=10)
        assert cipher.encrypt(b"abc") == b"abc"

    def test_empty_input(self) -> None:
        cipher = TruncateCipher(keep=4)
        assert cipher.encrypt(b"") == b""

    def test_keep_one_keeps_first_byte(self) -> None:
        cipher = TruncateCipher(keep=1)
        assert cipher.encrypt(b"hello") == b"h"

    def test_keep_one_tail_keeps_last_byte(self) -> None:
        cipher = TruncateCipher(keep=1, side=KEEP_TAIL)
        assert cipher.encrypt(b"hello") == b"o"

    def test_keep_larger_than_input(self) -> None:
        cipher = TruncateCipher(keep=100, side=KEEP_TAIL)
        assert cipher.encrypt(b"hi") == b"hi"

    def test_irreversible(self) -> None:
        assert_irreversible(TruncateCipher(keep=4), b"abcdefgh")

    def test_rejects_non_positive_keep(self) -> None:
        with pytest.raises(ValueError):
            TruncateCipher(keep=0)
        with pytest.raises(ValueError):
            TruncateCipher(keep=-1)

    def test_rejects_non_integer_keep(self) -> None:
        with pytest.raises(TypeError):
            TruncateCipher(keep=2.5)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            TruncateCipher(keep=True)  # type: ignore[arg-type]

    def test_rejects_unknown_side(self) -> None:
        with pytest.raises(ValueError):
            TruncateCipher(keep=3, side="middle")

    def test_encrypt_hex_matches_bytes(self) -> None:
        cipher = TruncateCipher(keep=3)
        assert cipher.encrypt_hex(b"abcdef") == "616263"

    def test_encrypt_b64_matches_bytes(self) -> None:
        cipher = TruncateCipher(keep=3)
        assert cipher.encrypt_b64(b"abcdef") == "YWJj"

    def test_describe_includes_parameters(self) -> None:
        cipher = TruncateCipher(keep=8, side=KEEP_TAIL)
        info = cipher.describe()
        assert info["algorithm"] == "truncate"
        assert info["decryptable"] is False
        assert info["parameters"] == {"keep": 8, "side": KEEP_TAIL}

    def test_equality_and_hash(self) -> None:
        assert TruncateCipher(keep=4) == TruncateCipher(keep=4)
        assert TruncateCipher(keep=4) != TruncateCipher(keep=5)
        assert TruncateCipher(keep=4, side=KEEP_TAIL) != TruncateCipher(keep=4)
        assert hash(TruncateCipher(keep=4)) == hash(TruncateCipher(keep=4))

    def test_repr_includes_parameters(self) -> None:
        cipher = TruncateCipher(keep=4, side=KEEP_TAIL)
        text = repr(cipher)
        assert "keep=4" in text
        assert "side" in text

    def test_rejects_non_bytes_input(self) -> None:
        cipher = TruncateCipher(keep=4)
        with pytest.raises(CipherError):
            cipher.encrypt("not bytes")  # type: ignore[arg-type]

    def test_pipeline_marks_cipher_as_irreversible(self) -> None:
        pl = Pipeline([TruncateCipher(keep=4)])
        assert pl.DECRYPTABLE is False
        with pytest.raises(CipherError):
            pl.decrypt(b"abcd")


# ---------------------------------------------------------------------------
# DiscardCipher
# ---------------------------------------------------------------------------
class TestDiscardCipher:
    def test_step_two_keeps_even_indexed_bytes(self) -> None:
        cipher = DiscardCipher(step=2)
        assert cipher.encrypt(b"abcdefgh") == b"aceg"

    def test_step_three_keeps_third_bytes(self) -> None:
        cipher = DiscardCipher(step=3)
        assert cipher.encrypt(b"abcdefghij") == b"adgj"

    def test_offset_shifts_position(self) -> None:
        cipher = DiscardCipher(step=2, offset=1)
        assert cipher.encrypt(b"abcdefgh") == b"bdfh"

    def test_step_one_keeps_everything(self) -> None:
        cipher = DiscardCipher(step=1)
        assert cipher.encrypt(b"abcdef") == b"abcdef"

    def test_step_larger_than_input_keeps_first_byte(self) -> None:
        # When the input is shorter than ``step`` the cipher keeps
        # the byte at position ``offset`` (the first byte by default).
        # range(0, 3, 10) yields [0], so we expect ``b"a"``.
        cipher = DiscardCipher(step=10)
        assert cipher.encrypt(b"abc") == b"a"

    def test_offset_aligns_to_step(self) -> None:
        cipher = DiscardCipher(step=10, offset=1)
        assert cipher.encrypt(b"abc") == b"b"

    def test_offset_beyond_input_returns_empty(self) -> None:
        cipher = DiscardCipher(step=10, offset=3)
        assert cipher.encrypt(b"abc") == b""

    def test_irreversible(self) -> None:
        assert_irreversible(DiscardCipher(step=2), b"abcdefghij")

    def test_output_never_longer_than_input(self) -> None:
        cipher = DiscardCipher(step=3)
        for length in range(0, 64):
            payload = bytes(range(length))
            assert len(cipher.encrypt(payload)) <= length

    def test_rejects_non_positive_step(self) -> None:
        with pytest.raises(ValueError):
            DiscardCipher(step=0)
        with pytest.raises(ValueError):
            DiscardCipher(step=-1)

    def test_rejects_non_integer_step(self) -> None:
        with pytest.raises(TypeError):
            DiscardCipher(step=1.5)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            DiscardCipher(step=True)  # type: ignore[arg-type]

    def test_rejects_offset_out_of_range(self) -> None:
        with pytest.raises(ValueError):
            DiscardCipher(step=4, offset=4)
        with pytest.raises(ValueError):
            DiscardCipher(step=4, offset=-1)

    def test_rejects_non_integer_offset(self) -> None:
        with pytest.raises(TypeError):
            DiscardCipher(step=4, offset=1.5)  # type: ignore[arg-type]

    def test_default_step_is_two(self) -> None:
        assert DEFAULT_STEP == 2
        assert DiscardCipher()._params["step"] == DEFAULT_STEP

    def test_encrypt_hex_and_b64(self) -> None:
        cipher = DiscardCipher(step=2)
        assert cipher.encrypt_hex(b"abcd") == "6163"
        assert cipher.encrypt_b64(b"abcd") == "YWM="

    def test_describe_includes_parameters(self) -> None:
        cipher = DiscardCipher(step=3, offset=1)
        info = cipher.describe()
        assert info["algorithm"] == "discard"
        assert info["decryptable"] is False
        assert info["parameters"] == {"step": 3, "offset": 1}

    def test_rejects_non_bytes_input(self) -> None:
        cipher = DiscardCipher(step=2)
        with pytest.raises(CipherError):
            cipher.encrypt(12345)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ScrambleCipher
# ---------------------------------------------------------------------------
class TestScrambleCipher:
    def test_output_is_permutation(self) -> None:
        cipher = ScrambleCipher(b"key")
        plain = b"abcdefghij"
        out = cipher.encrypt(plain)
        assert sorted(out) == sorted(plain)

    def test_output_length_matches_input(self) -> None:
        cipher = ScrambleCipher(b"key")
        for length in range(0, 32):
            payload = bytes(range(length))
            assert len(cipher.encrypt(payload)) == length

    def test_empty_input(self) -> None:
        cipher = ScrambleCipher(b"key")
        assert cipher.encrypt(b"") == b""

    def test_single_byte_is_identity(self) -> None:
        cipher = ScrambleCipher(b"key")
        assert cipher.encrypt(b"x") == b"x"

    def test_irreversible(self) -> None:
        assert_irreversible(ScrambleCipher(b"key"), b"hello world")

    def test_key_changes_output(self) -> None:
        plain = b"hello world!"
        a = ScrambleCipher(b"key-a").encrypt(plain)
        b = ScrambleCipher(b"key-b").encrypt(plain)
        assert a != b

    def test_rounds_change_output(self) -> None:
        plain = b"abcdefghijklmnop"
        one = ScrambleCipher(b"key", rounds=1).encrypt(plain)
        two = ScrambleCipher(b"key", rounds=2).encrypt(plain)
        assert one != two
        assert sorted(one) == sorted(two)

    def test_rejects_empty_key(self) -> None:
        with pytest.raises(ValueError):
            ScrambleCipher(b"")

    def test_rejects_non_positive_rounds(self) -> None:
        with pytest.raises(ValueError):
            ScrambleCipher(b"key", rounds=0)
        with pytest.raises(ValueError):
            ScrambleCipher(b"key", rounds=-1)

    def test_rejects_non_integer_rounds(self) -> None:
        with pytest.raises(TypeError):
            ScrambleCipher(b"key", rounds=1.5)  # type: ignore[arg-type]

    def test_same_key_is_deterministic(self) -> None:
        plain = b"hello world"
        a = ScrambleCipher(b"key").encrypt(plain)
        b = ScrambleCipher(b"key").encrypt(plain)
        assert a == b

    def test_default_rounds_is_one(self) -> None:
        assert ScrambleCipher(b"key")._params["rounds"] == 1

    def test_describe_includes_key(self) -> None:
        cipher = ScrambleCipher(b"key", rounds=2)
        info = cipher.describe()
        assert info["algorithm"] == "scramble"
        assert info["decryptable"] is False
        assert info["parameters"] == {"key": b"key", "rounds": 2}

    def test_rejects_non_bytes_input(self) -> None:
        cipher = ScrambleCipher(b"key")
        with pytest.raises(CipherError):
            cipher.encrypt("not bytes")  # type: ignore[arg-type]

    def test_byte_distribution_is_balanced(self) -> None:
        cipher = ScrambleCipher(b"key")
        plain = os.urandom(256)
        out = cipher.encrypt(plain)
        assert Counter(plain) == Counter(out)

    def test_pipeline_marks_cipher_as_irreversible(self) -> None:
        pl = Pipeline([ScrambleCipher(b"key")])
        assert pl.DECRYPTABLE is False


# ---------------------------------------------------------------------------
# BloomFingerprint
# ---------------------------------------------------------------------------
class TestBloomFingerprint:
    def test_default_size(self) -> None:
        cipher = BloomFingerprint()
        assert len(cipher.encrypt(b"hello")) == DEFAULT_SIZE

    def test_custom_size(self) -> None:
        cipher = BloomFingerprint(size=64)
        assert len(cipher.encrypt(b"hello")) == 64

    def test_hashes_set_multiple_bits(self) -> None:
        cipher = BloomFingerprint(size=16, hashes=4)
        fingerprint = cipher.encrypt(b"hello")
        # ``hashes`` distinct bit positions should be set, so at
        # least four bits are on in the 128-bit fingerprint.
        assert bin(int.from_bytes(fingerprint, "big")).count("1") >= 4

    def test_irreversible(self) -> None:
        assert_irreversible(BloomFingerprint(size=16), b"hello")

    def test_digest_is_deterministic(self) -> None:
        cipher = BloomFingerprint(size=16, hashes=4, salt=b"v1")
        a = cipher.encrypt(b"hello")
        b = cipher.encrypt(b"hello")
        assert a == b

    def test_salt_changes_digest(self) -> None:
        plain = b"hello"
        a = BloomFingerprint(size=16, hashes=4, salt=b"v1").encrypt(plain)
        b = BloomFingerprint(size=16, hashes=4, salt=b"v2").encrypt(plain)
        assert a != b

    def test_size_changes_digest(self) -> None:
        plain = b"hello"
        a = BloomFingerprint(size=16, hashes=4).encrypt(plain)
        b = BloomFingerprint(size=32, hashes=4).encrypt(plain)
        assert a != b

    def test_hashes_changes_digest(self) -> None:
        plain = b"hello"
        a = BloomFingerprint(size=64, hashes=2).encrypt(plain)
        b = BloomFingerprint(size=64, hashes=8).encrypt(plain)
        assert a != b

    def test_verify_matches_and_rejects_tampering(self) -> None:
        cipher = BloomFingerprint(size=16, hashes=4, salt=b"v1")
        digest = cipher.encrypt(b"hello")
        assert cipher.verify(b"hello", digest) is True
        assert cipher.verify(b"world", digest) is False

    def test_verify_rejects_tampered_digest(self) -> None:
        cipher = BloomFingerprint(size=16, hashes=4)
        digest = cipher.encrypt(b"hello")
        tampered = bytearray(digest)
        tampered[0] ^= 0x01
        assert cipher.verify(b"hello", bytes(tampered)) is False

    def test_verify_rejects_non_bytes(self) -> None:
        cipher = BloomFingerprint()
        with pytest.raises(CipherError):
            cipher.verify("hello", b"\\x00" * 16)  # type: ignore[arg-type]]

    def test_encrypt_hex_and_b64(self) -> None:
        cipher = BloomFingerprint(size=8, hashes=4)
        hex_digest = cipher.encrypt_hex(b"hello")
        assert len(hex_digest) == 16
        assert cipher.encrypt_b64(b"hello") != ""

    def test_rejects_non_positive_size(self) -> None:
        with pytest.raises(ValueError):
            BloomFingerprint(size=0)
        with pytest.raises(ValueError):
            BloomFingerprint(size=-1)

    def test_rejects_non_integer_size(self) -> None:
        with pytest.raises(TypeError):
            BloomFingerprint(size=2.5)  # type: ignore[arg-type]

    def test_rejects_non_positive_hashes(self) -> None:
        with pytest.raises(ValueError):
            BloomFingerprint(hashes=0)
        with pytest.raises(ValueError):
            BloomFingerprint(hashes=-1)

    def test_rejects_non_integer_hashes(self) -> None:
        with pytest.raises(TypeError):
            BloomFingerprint(hashes=2.5)  # type: ignore[arg-type]

    def test_rejects_non_bytes_salt(self) -> None:
        with pytest.raises(TypeError):
            BloomFingerprint(salt="not-bytes")  # type: ignore[arg-type]

    def test_describe_includes_parameters(self) -> None:
        cipher = BloomFingerprint(size=8, hashes=4, salt=b"v1")
        info = cipher.describe()
        assert info["algorithm"] == "bloom"
        assert info["decryptable"] is False
        assert info["parameters"] == {"size": 8, "hashes": 4, "salt": b"v1"}

    def test_positions_are_within_range(self) -> None:
        size = 8
        hashes = 4
        cipher = BloomFingerprint(size=size, hashes=hashes)
        positions = cipher._positions(b"hello")
        assert len(positions) == hashes
        for position in positions:
            assert 0 <= position < size * 8

    def test_more_hashes_than_digest_chunks(self) -> None:
        cipher = BloomFingerprint(size=16, hashes=16)
        fingerprint = cipher.encrypt(b"hello")
        assert len(fingerprint) == 16
        assert cipher.verify(b"hello", fingerprint) is True

    def test_pipeline_marks_cipher_as_irreversible(self) -> None:
        pl = Pipeline([BloomFingerprint(size=16)])
        assert pl.DECRYPTABLE is False
        with pytest.raises(CipherError):
            pl.decrypt(b"\x00" * 16)
