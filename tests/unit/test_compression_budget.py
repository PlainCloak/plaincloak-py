from __future__ import annotations

import brotli
import pytest

from plaincloak.core import compression
from plaincloak.exceptions import (
    DecompressedTooLargeError,
    DecompressionFailedError,
    UnknownCompressionError,
)


class TestRoundTrip:
    """Compress/decompress pairs return the original bytes."""

    @pytest.mark.parametrize(
        "data",
        [b"", b"hello world", b"a" * 4096, bytes(range(256)) * 4],
    )
    def test_brotli_roundtrip(self, data: bytes) -> None:
        out = compression.compress(data, code="BR")
        assert compression.decompress(out, code="BR") == data

    def test_identity_consume_returns_input(self) -> None:
        assert compression.decompress(b"hello", code="NO") == b"hello"

    def test_identity_produce_requires_internal_flag(self) -> None:
        with pytest.raises(UnknownCompressionError):
            compression.compress(b"hello", code="NO")

    def test_identity_produce_allowed_with_flag(self) -> None:
        assert compression.compress(b"hi", code="NO", _allow_no=True) == b"hi"


class TestRejection:
    """Reserved and unknown codes are rejected on both directions."""

    def test_zs_rejected_on_consume(self) -> None:
        with pytest.raises(UnknownCompressionError):
            compression.decompress(b"\x00", code="ZS")

    def test_zs_rejected_on_produce(self) -> None:
        with pytest.raises(UnknownCompressionError):
            compression.compress(b"\x00", code="ZS")

    def test_unknown_code_rejected(self) -> None:
        with pytest.raises(UnknownCompressionError):
            compression.decompress(b"\x00", code="XX")

    def test_invalid_brotli_stream_rejected(self) -> None:
        with pytest.raises(DecompressionFailedError):
            compression.decompress(b"\xff\xff\xff\xff", code="BR")


class TestBudget:
    """Streaming budget aborts on oversized output."""

    def test_brotli_bomb_aborts_before_full_decompression(self) -> None:
        # 4 MiB of zeros compresses tiny under Brotli quality 11.
        bomb = brotli.compress(b"\x00" * (4 * 1024 * 1024), quality=11)
        assert len(bomb) < 4096, "test setup expected a high-ratio bomb"
        with pytest.raises(DecompressedTooLargeError):
            compression.decompress(bomb, code="BR")

    def test_budget_respected_for_legitimate_payload(self) -> None:
        data = b"x" * 10_000
        out = compression.compress(data, code="BR")
        assert compression.decompress(out, code="BR", budget_bytes=64_000) == data

    def test_budget_rejects_within_legitimate_payload(self) -> None:
        data = b"x" * 10_000
        out = compression.compress(data, code="BR")
        with pytest.raises(DecompressedTooLargeError):
            compression.decompress(out, code="BR", budget_bytes=4_096)

    def test_identity_oversized_rejected(self) -> None:
        with pytest.raises(DecompressedTooLargeError):
            compression.decompress(b"x" * 1000, code="NO", budget_bytes=100)
