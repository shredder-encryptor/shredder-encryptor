"""Tests for :mod:`shredder_encryptor.cipher`."""

from __future__ import annotations

import os

import pytest

from shredder_encryptor.cipher import (
    BLOCK_SIZE,
    ROUNDS,
    FeistelCbcCipher,
    FeistelEcbCipher,
    Sha256Hash,
    VigenereCipher,
    XorStreamCipher,
)
from shredder_encryptor.framework import (
    Pipeline,
    assert_irreversible,
    assert_round_trip,
)


# ---------------------------------------------------------------------------
# VigenereCipher
# ---------------------------------------------------------------------------
class TestVigenereCipher:
    def test_round_trip(self) -> None:
        assert_round_trip(VigenereCipher(b"key"), b"Hello, world!")

    def test_empty_key_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            VigenereCipher(b"")

    def test_text_helper_round_trip(self) -> None:
        cipher = VigenereCipher(b"key")
        assert cipher.decrypt_text(cipher.encrypt_text("héllo")) == "héllo"


# ---------------------------------------------------------------------------
# XorStreamCipher
# ---------------------------------------------------------------------------
class TestXorStreamCipher:
    def test_round_trip(self) -> None:
        assert_round_trip(XorStreamCipher(b"secret"), b"the quick brown fox")

    def test_nonce_changes_cipher_text(self) -> None:
        plain = b"hello"
        a = XorStreamCipher(b"key", nonce=b"n1").encrypt(plain)
        b = XorStreamCipher(b"key", nonce=b"n2").encrypt(plain)
        assert a != b

    def test_empty_key_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            XorStreamCipher(b"")


# ---------------------------------------------------------------------------
# Feistel ciphers (ECB / CBC)
# ---------------------------------------------------------------------------
class TestFeistelCiphers:
    def test_ecb_buffer_round_trip(self) -> None:
        cipher = FeistelEcbCipher(b"my-key")
        for n in (0, 1, 7, 8, 9, 16, 33, 257, 1024):
            pt = os.urandom(n)
            assert cipher.decrypt(cipher.encrypt(pt)) == pt

    def test_cbc_buffer_round_trip(self) -> None:
        cipher = FeistelCbcCipher(b"my-key")
        for n in (0, 1, 7, 8, 9, 16, 33, 257, 1024):
            pt = os.urandom(n)
            assert cipher.decrypt(cipher.encrypt(pt)) == pt

    def test_cbc_uses_random_iv(self) -> None:
        cipher = FeistelCbcCipher(b"k")
        plain = b"same plaintext"
        a = cipher.encrypt(plain)
        b = cipher.encrypt(plain)
        assert a != b
        assert cipher.decrypt(a) == plain
        assert cipher.decrypt(b) == plain

    def test_ecb_single_block_round_trip(self) -> None:
        cipher = FeistelEcbCipher(b"k")
        block = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        assert cipher.decrypt_block(cipher.encrypt_block(block)) == block

    def test_ecb_invalid_block_size(self) -> None:
        cipher = FeistelEcbCipher(b"k")
        with pytest.raises(ValueError):
            cipher.encrypt_block(b"abc")
        with pytest.raises(ValueError):
            cipher.decrypt_block(b"abc")

    def test_ecb_rejects_oversize_ciphertext(self) -> None:
        cipher = FeistelEcbCipher(b"k")
        with pytest.raises(ValueError):
            cipher.decrypt(b"abc")

    def test_cbc_rejects_short_ciphertext(self) -> None:
        cipher = FeistelCbcCipher(b"k")
        with pytest.raises(ValueError):
            cipher.decrypt(b"short")

    def test_key_validation(self) -> None:
        for bad_key in (b"", b"x" * 9):
            with pytest.raises(ValueError):
                FeistelEcbCipher(bad_key)

    def test_constants(self) -> None:
        assert BLOCK_SIZE == 8
        assert ROUNDS == 16


# ---------------------------------------------------------------------------
# Sha256Hash (one-way)
# ---------------------------------------------------------------------------
class TestSha256Hash:
    def test_irreversible(self) -> None:
        assert_irreversible(Sha256Hash(), b"hello")

    def test_verify_matches_and_rejects_tampering(self) -> None:
        h = Sha256Hash(salt=b"v1")
        digest = h.encrypt(b"hello")
        assert h.verify(b"hello", digest) is True
        assert h.verify(b"world", digest) is False
        assert h.verify(b"hello", digest[:-1] + b"\x00") is False

    def test_hex_helpers(self) -> None:
        h = Sha256Hash()
        hex_digest = h.encrypt_hex(b"hello")
        assert len(hex_digest) == 64
        assert h.verify_hex(b"hello", hex_digest) is True
        assert h.verify_hex(b"world", hex_digest) is False


# ---------------------------------------------------------------------------
# Pipeline composition
# ---------------------------------------------------------------------------
class TestPipelines:
    def test_ecb_vigenere_pipeline(self) -> None:
        pl = Pipeline([FeistelEcbCipher(b"k1"), VigenereCipher(b"v1")])
        assert_round_trip(pl, b"combo" * 8)

    def test_cbc_stream_pipeline(self) -> None:
        pl = Pipeline([FeistelCbcCipher(b"k"), XorStreamCipher(b"s")])
        assert_round_trip(pl, b"another combo" * 4)
