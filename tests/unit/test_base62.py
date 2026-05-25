from __future__ import annotations

import os

import pytest

from plaincloak.core import base62
from plaincloak.exceptions import InvalidBase62Error


class TestEncodeFixedCases:
    """Worked examples from spec section 4.2."""

    def test_empty_input_encodes_to_empty_string(self) -> None:
        assert base62.encode(b"") == ""

    def test_single_zero_byte_encodes_to_zero_char(self) -> None:
        assert base62.encode(b"\x00") == "0"

    def test_two_zero_bytes_encode_to_two_zeros(self) -> None:
        assert base62.encode(b"\x00\x00") == "00"

    def test_one_byte_value_1_encodes_to_1(self) -> None:
        assert base62.encode(b"\x01") == "1"

    def test_leading_zero_prefix_preserved(self) -> None:
        assert base62.encode(b"\x00\xff") == "047"


class TestDecodeFixedCases:
    """Worked examples from spec section 4.3."""

    def test_empty_string_decodes_to_empty_bytes(self) -> None:
        assert base62.decode("") == b""

    def test_zero_char_decodes_to_single_zero_byte(self) -> None:
        assert base62.decode("0") == b"\x00"

    def test_double_zero_decodes_to_two_zero_bytes(self) -> None:
        assert base62.decode("00") == b"\x00\x00"


class TestRejection:
    """Decoder rejects characters outside the alphabet."""

    @pytest.mark.parametrize("bad", ["!", "/", "+", "=", " ", ":", "\n", "ü"])
    def test_non_alphabet_character_raises(self, bad: str) -> None:
        with pytest.raises(InvalidBase62Error):
            base62.decode(f"abc{bad}def")


class TestRoundTrip:
    """Round-trip property: decode(encode(x)) == x for arbitrary bytes."""

    @pytest.mark.parametrize("size", [0, 1, 2, 16, 64, 256, 1024])
    def test_random_roundtrip(self, size: int) -> None:
        data = os.urandom(size)
        assert base62.decode(base62.encode(data)) == data

    def test_leading_zero_rich_roundtrip(self) -> None:
        data = b"\x00" * 8 + b"hello"
        assert base62.decode(base62.encode(data)) == data
