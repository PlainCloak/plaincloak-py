from __future__ import annotations

import pytest

from plaincloak.core import base62
from plaincloak.core.envelope import (
    ParsedEnvelope,
    format_envelope,
    parse_envelope,
)
from plaincloak.exceptions import (
    InvalidBase62Error,
    MalformedWireError,
    UnknownCompressionError,
    UnsupportedVersionError,
)


def _wire(payload_bytes: bytes, *, comp: str = "BR", version: str = "v1") -> str:
    return f"PLAINCLOAK:{version}:{comp}:{base62.encode(payload_bytes)}"


class TestParseAcceptance:
    """Well-formed inputs return the expected fields."""

    def test_minimal_valid_wire(self) -> None:
        parsed = parse_envelope(_wire(b"\xde\xad\xbe\xef"))
        assert isinstance(parsed, ParsedEnvelope)
        assert parsed.wire_version_int == 1
        assert parsed.version_token == "v1"
        assert parsed.comp_code == "BR"
        assert parsed.payload_bytes == b"\xde\xad\xbe\xef"

    def test_no_codec_accepted_on_consume(self) -> None:
        parsed = parse_envelope(_wire(b"\x01\x02\x03", comp="NO"))
        assert parsed.comp_code == "NO"
        assert parsed.payload_bytes == b"\x01\x02\x03"

    @pytest.mark.parametrize("tail", ["\n", "\r\n", " ", "\t", "  \n"])
    def test_trailing_whitespace_tolerated(self, tail: str) -> None:
        # Spec section 3.3 step 5: whitespace terminates the payload.
        parsed = parse_envelope(_wire(b"\xde\xad") + tail)
        assert parsed.payload_bytes == b"\xde\xad"


class TestMagicAndStructure:
    """Magic, colon-count, and ASCII-only enforcement."""

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(MalformedWireError):
            parse_envelope("")

    def test_lowercase_magic_rejected(self) -> None:
        with pytest.raises(MalformedWireError):
            parse_envelope("plaincloak:v1:BR:abc")

    def test_three_colons_required(self) -> None:
        # Two colons -> three fields.
        with pytest.raises(MalformedWireError):
            parse_envelope("PLAINCLOAK:v1:BR")

    def test_chunked_form_rejected_extra_colon(self) -> None:
        # Reserved chunked form from spec section 3.5.
        with pytest.raises(MalformedWireError):
            parse_envelope("PLAINCLOAK:v1:BR:1/3:ABCdef")

    def test_non_ascii_rejected(self) -> None:
        with pytest.raises(MalformedWireError):
            parse_envelope("PLAINCLOAK:v1:BR:abcé")


class TestVersionAndCompression:
    """Version-token and comp-code rejection paths."""

    def test_v2_rejected_as_unsupported(self) -> None:
        with pytest.raises(UnsupportedVersionError):
            parse_envelope(_wire(b"\x00", version="v2"))

    def test_uppercase_version_rejected(self) -> None:
        with pytest.raises(UnsupportedVersionError):
            parse_envelope(_wire(b"\x00", version="V1"))

    def test_version_checked_before_payload_shape(self) -> None:
        # Spec 3.3 order: step 3 (version) fires before the payload is
        # examined, even when the payload has extra colons.
        with pytest.raises(UnsupportedVersionError):
            parse_envelope("PLAINCLOAK:v2:BR:a:b")

    def test_compression_checked_before_payload_shape(self) -> None:
        with pytest.raises(UnknownCompressionError):
            parse_envelope("PLAINCLOAK:v1:XX:a:b")

    def test_reserved_zs_rejected(self) -> None:
        with pytest.raises(UnknownCompressionError):
            parse_envelope(_wire(b"\x00", comp="ZS"))

    def test_unknown_compression_rejected(self) -> None:
        with pytest.raises(UnknownCompressionError):
            parse_envelope(_wire(b"\x00", comp="XX"))

    def test_one_letter_compression_rejected(self) -> None:
        with pytest.raises(UnknownCompressionError):
            parse_envelope("PLAINCLOAK:v1:B:abc")

    def test_numeric_compression_rejected(self) -> None:
        with pytest.raises(UnknownCompressionError):
            parse_envelope("PLAINCLOAK:v1:B1:abc")


class TestPayload:
    """Payload presence and Base62 alphabet enforcement."""

    def test_empty_payload_rejected(self) -> None:
        with pytest.raises(MalformedWireError):
            parse_envelope("PLAINCLOAK:v1:BR:")

    def test_payload_with_invalid_char_rejected(self) -> None:
        with pytest.raises(InvalidBase62Error):
            parse_envelope("PLAINCLOAK:v1:BR:abc+def")

    def test_internal_whitespace_rejected(self) -> None:
        with pytest.raises(InvalidBase62Error):
            parse_envelope("PLAINCLOAK:v1:BR:abc def")

    def test_leading_whitespace_rejected(self) -> None:
        with pytest.raises(MalformedWireError):
            parse_envelope("  PLAINCLOAK:v1:BR:abc")


class TestFormat:
    """Round-trip of `format_envelope` against `parse_envelope`."""

    def test_format_then_parse_roundtrip(self) -> None:
        original = b"some compressed bytes"
        wire = format_envelope(comp_code="BR", payload_bytes=original)
        parsed = parse_envelope(wire)
        assert parsed.payload_bytes == original
        assert parsed.comp_code == "BR"

    def test_format_rejects_empty_payload(self) -> None:
        with pytest.raises(MalformedWireError):
            format_envelope(comp_code="BR", payload_bytes=b"")

    def test_format_rejects_no_codec(self) -> None:
        with pytest.raises(UnknownCompressionError):
            format_envelope(comp_code="NO", payload_bytes=b"\x01")

    def test_format_rejects_unknown_codec(self) -> None:
        with pytest.raises(UnknownCompressionError):
            format_envelope(comp_code="XX", payload_bytes=b"\x01")
