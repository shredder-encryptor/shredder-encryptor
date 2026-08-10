"""Tests for :mod:`shredder_encryptor.framework`."""

from __future__ import annotations

import pytest

from shredder_encryptor.framework import (
    BaseCipher,
    CipherError,
    Pipeline,
    assert_irreversible,
    assert_round_trip,
    encrypt,
    decrypt,
    fuzz_cipher,
    random_bytes,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
class RotCipher(BaseCipher):
    """Toy reversible cipher used by the framework tests."""

    algorithm = "rot"
    DECRYPTABLE = True

    def __init__(self, offset=3):
        super().__init__(offset=offset)

    def encrypt(self, plaintext):
        clean = self._require_bytes(plaintext, "plaintext")
        return bytes((b + self._params["offset"]) % 256 for b in clean)

    def decrypt(self, ciphertext):
        clean = self._require_bytes(ciphertext, "ciphertext")
        return bytes((b - self._params["offset"]) % 256 for b in clean)


class IdentityHash(BaseCipher):
    """Non-decryptable cipher used by the framework tests."""

    algorithm = "identity-hash"
    DECRYPTABLE = False

    def __init__(self, marker=b"!"):
        super().__init__(marker=marker)

    def encrypt(self, plaintext):
        return self._require_bytes(plaintext, "plaintext") + self._params["marker"]


# ---------------------------------------------------------------------------
# BaseCipher
# ---------------------------------------------------------------------------
class TestBaseCipher:
    def test_name_includes_class_and_algorithm(self) -> None:
        cipher = RotCipher(offset=1)
        assert cipher.name == "RotCipher:rot"

    def test_repr_contains_parameters(self) -> None:
        cipher = RotCipher(offset=5)
        assert "offset=5" in repr(cipher)

    def test_equality_and_hash(self) -> None:
        assert RotCipher(offset=2) == RotCipher(offset=2)
        assert RotCipher(offset=2) != RotCipher(offset=3)
        assert hash(RotCipher(offset=2)) == hash(RotCipher(offset=2))

    def test_describe_returns_dict(self) -> None:
        cipher = RotCipher(offset=7)
        info = cipher.describe()
        assert info["algorithm"] == "rot"
        assert info["parameters"] == {"offset": 7}

    def test_require_bytes_rejects_non_bytes(self) -> None:
        with pytest.raises(CipherError):
            BaseCipher._require_bytes("hi", "data")  # type: ignore[arg-type]

    def test_default_decrypt_raises_for_non_decryptable(self) -> None:
        cipher = IdentityHash()
        with pytest.raises(CipherError):
            cipher.decrypt(b"hi!")

    def test_default_decrypt_raises_not_implemented(self) -> None:
        class Half(BaseCipher):
            algorithm = "half"
            DECRYPTABLE = True

            def encrypt(self, plaintext):
                return plaintext

        with pytest.raises(NotImplementedError):
            Half().decrypt(b"hi")


# ---------------------------------------------------------------------------
# Pipeline + module helpers
# ---------------------------------------------------------------------------
class TestPipeline:
    def test_pipeline_encrypt_decrypt_round_trip(self) -> None:
        pl = Pipeline([RotCipher(offset=1), RotCipher(offset=2)])
        assert_round_trip(pl, b"hello")

    def test_pipeline_rejects_non_cipher_members(self) -> None:
        with pytest.raises(CipherError):
            Pipeline([RotCipher(offset=1), "not a cipher"])  # type: ignore[list-item]

    def test_pipeline_decrypt_rejects_non_decryptable(self) -> None:
        pl = Pipeline([RotCipher(offset=1), IdentityHash()])
        with pytest.raises(CipherError):
            pl.decrypt(b"hello!")

    def test_pipeline_append_returns_new_instance(self) -> None:
        pl = Pipeline([RotCipher(offset=1)])
        pl2 = pl.append(RotCipher(offset=2))
        assert len(pl) == 1 and len(pl2) == 2

    def test_pipeline_add_and_radd(self) -> None:
        pl = Pipeline([RotCipher(offset=1)]) + RotCipher(offset=2)
        assert len(pl) == 2
        pl2 = RotCipher(offset=0) + Pipeline([RotCipher(offset=1)])
        assert len(pl2) == 2

    def test_module_level_encrypt_decrypt(self) -> None:
        cipher = RotCipher(offset=4)
        ct = encrypt(b"hi", cipher)
        assert decrypt(ct, cipher) == b"hi"

    def test_pipeline_decryptable_property(self) -> None:
        pl = Pipeline([RotCipher(offset=1), RotCipher(offset=2)])
        assert pl.DECRYPTABLE is True
        pl_bad = Pipeline([RotCipher(offset=1), IdentityHash()])
        assert pl_bad.DECRYPTABLE is False

    def test_pipeline_equality(self) -> None:
        a = Pipeline([RotCipher(offset=1)])
        b = Pipeline([RotCipher(offset=1)])
        c = Pipeline([RotCipher(offset=2)])
        assert a == b
        assert a != c


# ---------------------------------------------------------------------------
# Testing helpers
# ---------------------------------------------------------------------------
class TestAssertHelpers:
    def test_assert_round_trip_succeeds(self) -> None:
        assert_round_trip(RotCipher(offset=1), b"hello")

    def test_assert_round_trip_reports_mismatch(self) -> None:
        cipher = RotCipher(offset=3)
        with pytest.raises(AssertionError):
            assert_round_trip(cipher, b"hello", expected=b"different")

    def test_assert_round_trip_rejects_non_decryptable(self) -> None:
        with pytest.raises(AssertionError):
            assert_round_trip(IdentityHash(), b"x")

    def test_assert_irreversible(self) -> None:
        assert_irreversible(IdentityHash(), b"hello")

    def test_assert_irreversible_rejects_reversible(self) -> None:
        with pytest.raises(AssertionError):
            assert_irreversible(RotCipher(), b"x")


class TestFuzzAndRandom:
    def test_fuzz_cipher_runs_all_inputs(self) -> None:
        cipher = RotCipher(offset=2)
        results = fuzz_cipher(cipher, [b"hi", b"world", b"!"], iterations=3)
        assert len(results) == 3

    def test_fuzz_cipher_rejects_bad_iterations(self) -> None:
        with pytest.raises(ValueError):
            fuzz_cipher(RotCipher(), [b"hi"], iterations=0)

    def test_random_bytes_length_and_max_byte(self) -> None:
        sample = random_bytes(64, seed=1, max_byte=128)
        assert len(sample) == 64
        assert max(sample) < 128

    def test_random_bytes_rejects_negative_length(self) -> None:
        with pytest.raises(ValueError):
            random_bytes(-1)

    def test_random_bytes_rejects_bad_max_byte(self) -> None:
        with pytest.raises(ValueError):
            random_bytes(8, max_byte=0)
        with pytest.raises(ValueError):
            random_bytes(8, max_byte=257)
