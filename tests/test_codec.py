"""Tests for :mod:`shredder_encryptor.codec`.

The module exercises every public helper shipped by the
``codec`` package.  Tests are written with pytest so each case is a
plain function and fixtures are used wherever possible.
"""

from __future__ import annotations

import pytest

from shredder_encryptor import codec
from shredder_encryptor.codec import (
    ascii85,
    b64,
    digest,
    hexutil,
    padding,
    quoted_printable,
    text,
    token,
    url,
)


def _normalize(form, value):
    import unicodedata

    return unicodedata.normalize(form, value)


# ---------------------------------------------------------------------------
# text
# ---------------------------------------------------------------------------
class TestText:
    def test_to_bytes_accepts_str(self) -> None:
        assert codec.to_bytes("hi") == b"hi"

    def test_to_bytes_passes_through_bytes_like(self) -> None:
        assert codec.to_bytes(b"abc") == b"abc"
        assert codec.to_bytes(bytearray(b"abc")) == b"abc"
        assert codec.to_bytes(memoryview(b"abc")) == b"abc"

    def test_to_bytes_rejects_non_text(self) -> None:
        with pytest.raises(TypeError):
            codec.to_bytes(123)  # type: ignore[arg-type]

    def test_from_bytes_round_trip(self) -> None:
        assert codec.from_bytes(b"hi") == "hi"
        assert codec.from_bytes(bytearray(b"hi")) == "hi"

    def test_from_bytes_rejects_non_bytes_like(self) -> None:
        with pytest.raises(TypeError):
            codec.from_bytes(123)  # type: ignore[arg-type]

    def test_normalize_short_aliases(self) -> None:
        for alias, form in (("c", "NFC"), ("kc", "NFKC"), ("d", "NFD"), ("kd", "NFKD")):
            assert codec.normalize("é", alias) == _normalize(form, "é")

    def test_normalize_rejects_bad_form(self) -> None:
        with pytest.raises(ValueError):
            codec.normalize("x", "NFZZ")

    def test_safe_str_handles_invalid_bytes(self) -> None:
        assert codec.safe_str(b"hi\xff") == "hi\ufffd"

    def test_safe_str_passes_through_strings(self) -> None:
        assert codec.safe_str("hi") == "hi"

    def test_chunk_rejects_non_positive_size(self) -> None:
        with pytest.raises(ValueError):
            list(codec.chunk("abc", 0))

    def test_chunk_yields_expected_windows(self) -> None:
        assert list(codec.chunk("abcdef", 2)) == ["ab", "cd", "ef"]

    def test_codepoint_distribution_sorted_by_count(self) -> None:
        assert codec.codepoint_distribution("aabcc") == [("a", 2), ("c", 2), ("b", 1)]


# ---------------------------------------------------------------------------
# hexutil
# ---------------------------------------------------------------------------
class TestHexUtil:
    def test_to_hex_default_is_lower(self) -> None:
        assert codec.to_hex(b"\x00\xab\xcd") == "00abcd"

    def test_to_hex_upper(self) -> None:
        assert codec.to_hex(b"\x00\xab\xcd", case="upper") == "00ABCD"

    def test_to_hex_rejects_bad_case(self) -> None:
        with pytest.raises(ValueError):
            codec.to_hex(b"x", case="mixed")

    def test_from_hex_and_round_trip(self) -> None:
        assert codec.from_hex("00ABCD") == b"\x00\xab\xcd"
        assert codec.from_hex("") == b""

    def test_from_hex_invalid_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            codec.from_hex("not-hex")

    def test_is_hex(self) -> None:
        assert codec.is_hex("00ab") is True
        assert codec.is_hex("0x00ab") is False
        assert codec.is_hex("") is False
        assert codec.is_hex("xx") is False

    def test_hex_to_int_with_prefix_and_padding(self) -> None:
        assert codec.hex_to_int("0x10") == 16
        assert codec.hex_to_int("  -10  ") == -16

    def test_int_to_hex_round_trip(self) -> None:
        assert codec.int_to_hex(255) == "ff"
        assert codec.int_to_hex(255, case="upper") == "FF"
        assert codec.int_to_hex(-16) == "-10"
        assert codec.int_to_hex(255, prefix=True) == "0xff"
        assert codec.from_hex(codec.int_to_hex(0xCAFE)) == b"\xca\xfe"

    def test_int_to_hex_rejects_bool(self) -> None:
        with pytest.raises(TypeError):
            codec.int_to_hex(True)  # type: ignore[arg-type]

    def test_normalize_hex_uppercase(self) -> None:
        assert codec.normalize_hex("00ab cd", case="upper") == "00ABCD"


# ---------------------------------------------------------------------------
# b64
# ---------------------------------------------------------------------------
class TestBase64:
    def test_encode_decode_round_trip(self) -> None:
        data = b"hello\x00\xff"
        encoded = codec.encode(data)
        assert codec.decode(encoded) == data

    def test_decode_url_safe(self) -> None:
        payload = b"\xfb\xff\xfe?"  # bytes that include + or / in base64
        encoded = codec.encode_url(payload)
        assert codec.decode_url(encoded) == payload
        assert encoded != codec.encode(payload)

    def test_is_base64(self) -> None:
        assert codec.is_base64(codec.encode(b"x")) is True
        assert codec.is_base64("@@") is False
        assert codec.is_base64("a") is False
        assert codec.is_base64(codec.encode_url(b"x"), alphabet="url") is True
        # A standard base64 string that uses only URL-safe characters
        # (for example one that does not contain ``+`` or ``/``) is
        # trivially also valid URL-safe base64, so the alphabet
        # distinction only matters when the two encodings differ.

    def test_b64_int_round_trip(self) -> None:
        for value in (0, 1, 255, 0xDEAD_BEEF):
            encoded = codec.int_to_b64(value, min_length=4)
            assert codec.b64_to_int(encoded) == value

    def test_decode_with_validate(self) -> None:
        encoded = codec.encode(b"hi")
        with pytest.raises(ValueError):
            codec.decode(encoded + "!", validate=True)

    def test_encode_accepts_bytearray(self) -> None:
        assert codec.encode(bytearray(b"abc")) == codec.encode(b"abc")


# ---------------------------------------------------------------------------
# padding
# ---------------------------------------------------------------------------
class TestPadding:
    def test_required_padding_length_full_block(self) -> None:
        assert codec.required_padding_length(8, 8) == 8
        assert codec.required_padding_length(5, 8) == 3
        assert codec.required_padding_length(0, 8) == 8

    def test_pkcs7_round_trip(self) -> None:
        for length in (0, 1, 7, 8, 9, 16, 33):
            data = bytes(range(length))
            padded = codec.pkcs7_pad(data, 8)
            assert len(padded) % 8 == 0
            assert codec.pkcs7_unpad(padded, 8) == data

    def test_pkcs7_invalid_block_size(self) -> None:
        with pytest.raises(ValueError):
            codec.pkcs7_pad(b"x", 1)
        with pytest.raises(ValueError):
            codec.pkcs7_unpad(b"x", 0)

    def test_pkcs7_unpad_rejects_bad_padding(self) -> None:
        with pytest.raises(ValueError):
            codec.pkcs7_unpad(b"abc\x00\x00\x00\x00\x00", 8)

    def test_zero_pad_round_trip(self) -> None:
        assert codec.zero_unpad(codec.zero_pad(b"hi", 8)) == b"hi"
        assert codec.zero_pad(b"abcdefgh", 8) == b"abcdefgh"


# ---------------------------------------------------------------------------
# digest
# ---------------------------------------------------------------------------
class TestDigest:
    def test_sha256_known_vector(self) -> None:
        assert digest.digest(b"") == bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_sha1_known_vector(self) -> None:
        assert (
            digest.hexdigest(b"abc", "sha1")
            == "a9993e364706816aba3e25717850c26c9cd0d89d"
        )

    def test_supported_algorithms_is_sorted(self) -> None:
        algos = digest.supported_algorithms()
        assert algos == sorted(algos)
        assert "sha256" in algos

    def test_invalid_algorithm_raises(self) -> None:
        with pytest.raises(ValueError):
            digest.digest(b"x", "no-such-thing")

    def test_shake_requires_length(self) -> None:
        with pytest.raises(ValueError):
            digest.digest(b"x", "shake_128")
        assert len(digest.digest(b"x", "shake_128", length=16)) == 16

    def test_hexdigest_matches_digest(self) -> None:
        assert digest.hexdigest(b"hello") == digest.digest(b"hello").hex()


# ---------------------------------------------------------------------------
# token
# ---------------------------------------------------------------------------
class TestToken:
    def test_token_bytes_returns_correct_length(self) -> None:
        assert len(codec.token_bytes(16)) == 16
        assert codec.token_bytes(0) == b""

    def test_token_hex_and_urlsafe_have_expected_lengths(self) -> None:
        assert len(codec.token_hex(8)) == 16
        urlsafe = codec.token_urlsafe(8)
        assert isinstance(urlsafe, str) and urlsafe

    def test_token_rejects_negative_length(self) -> None:
        with pytest.raises(ValueError):
            codec.token_bytes(-1)

    def test_new_token_uses_alphabet(self) -> None:
        alphabet = "abc"
        tok = codec.new_token(64, alphabet=alphabet)
        assert len(tok) == 64
        assert set(tok) <= set(alphabet)

    def test_new_token_rejects_duplicates(self) -> None:
        with pytest.raises(ValueError):
            codec.new_token(8, alphabet="aabb")

    def test_constant_time_eq(self) -> None:
        assert codec.constant_time_eq(b"abc", "abc")
        assert not codec.constant_time_eq(b"abc", b"abd")
        assert not codec.constant_time_eq(b"abc", b"abcd")

    def test_token_bytes_looks_random(self) -> None:
        assert codec.token_bytes(16) != codec.token_bytes(16)


# ---------------------------------------------------------------------------
# url
# ---------------------------------------------------------------------------
class TestUrl:
    def test_quote_and_unquote(self) -> None:
        assert codec.quote("a b/c") == "a%20b/c"
        assert codec.unquote("a%20b/c") == "a b/c"

    def test_quote_bytes(self) -> None:
        assert codec.quote(b"a b") == "a%20b"

    def test_urlencode_and_urldecode(self) -> None:
        encoded = codec.urlencode({"q": "hello world", "x": "1"})
        assert codec.urldecode(encoded) == [("q", "hello world"), ("x", "1")]

    def test_urldecode_handles_plus(self) -> None:
        assert codec.urldecode("a=1+2") == [("a", "1 2")]


# ---------------------------------------------------------------------------
# quoted_printable, uuencode, ascii85
# ---------------------------------------------------------------------------
class TestQuotedPrintable:
    def test_encode_decode(self) -> None:
        data = b"hello\xff world"
        encoded = codec.encode_qp(data)
        assert codec.decode_qp(encoded) == data


class TestUuEncode:
    def test_round_trip(self) -> None:
        data = b"hello world"
        assert codec.uudecode(codec.uuencode(data)) == data


class TestAscii85:
    def test_adobe_round_trip(self) -> None:
        data = b"hello world" * 5
        assert codec.decode_ascii85(codec.encode_ascii85(data)) == data

    def test_git_round_trip(self) -> None:
        data = b"\x00\xff\x10abc"
        assert codec.decode_ascii85_adb(codec.encode_ascii85_adb(data)) == data


# ---------------------------------------------------------------------------
# Module-level smoke
# ---------------------------------------------------------------------------
def test_codec_package_exposes_submodules() -> None:
    for name in (
        "ascii85",
        "b64",
        "digest",
        "hexutil",
        "padding",
        "quoted_printable",
        "text",
        "token",
        "url",
        "uuencode",
    ):
        assert hasattr(codec, name)


def test_imports_match_attributes() -> None:
    assert codec.encode is b64.encode
    assert codec.pkcs7_pad is padding.pkcs7_pad
    assert codec.to_hex is hexutil.to_hex
    assert codec.token_bytes is token.token_bytes
    assert codec.digest_bytes is digest.digest
    assert codec.encode_ascii85 is ascii85.encode_ascii85
    # ``codec.uuencode`` shadows the module name; verify the function
    # is callable instead of comparing identities.
    assert callable(codec.uuencode)
    assert codec.encode_qp is quoted_printable.encode_qp
    assert codec.quote is url.quote
    assert codec.normalize is text.normalize
