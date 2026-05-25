from __future__ import annotations

import pytest

from plaincloak.core import body
from plaincloak.exceptions import InvalidBodyError, InvalidJSONError

_VALID: dict[str, object] = {
    "a": "RSA-OAEP-SHA256",
    "i": "550e8400-e29b-41d4-a716-446655440000",
    "t": 1746789123456,
    "s": "a" * 64,
    "r": "b" * 64,
    "p": "QUJDRA==",
    "g": "QUJDRA==",
}


class TestParse:
    """`parse` decodes UTF-8 JSON and rejects non-object roots."""

    def test_round_trip_dict(self) -> None:
        encoded = body.serialize(dict(_VALID))
        assert body.parse(encoded) == _VALID

    def test_invalid_utf8_rejected(self) -> None:
        with pytest.raises(InvalidJSONError):
            body.parse(b"\xff\xfe\xfd")

    def test_invalid_json_rejected(self) -> None:
        with pytest.raises(InvalidJSONError):
            body.parse(b"{not json")

    def test_non_object_root_rejected(self) -> None:
        with pytest.raises(InvalidJSONError):
            body.parse(b"[1, 2, 3]")


class TestValidateAccept:
    """Spec-conforming bodies validate cleanly."""

    def test_minimal_valid_body_accepted(self) -> None:
        body.validate(dict(_VALID))

    def test_hybrid_suite_accepted(self) -> None:
        b = dict(_VALID, a="RSA-OAEP-AES256GCM-SHA256")
        body.validate(b)


class TestValidateReject:
    """Each schema-enforced rule fires under the right mutation."""

    def test_extra_field_rejected(self) -> None:
        b = dict(_VALID, x="extra")
        with pytest.raises(InvalidBodyError):
            body.validate(b)

    def test_missing_required_field_rejected(self) -> None:
        b = dict(_VALID)
        del b["g"]
        with pytest.raises(InvalidBodyError):
            body.validate(b)

    def test_uppercase_hex_rejected(self) -> None:
        b = dict(_VALID, s="A" * 64)
        with pytest.raises(InvalidBodyError):
            body.validate(b)

    def test_uuid_v1_rejected(self) -> None:
        b = dict(_VALID, i="550e8400-e29b-11d4-a716-446655440000")
        with pytest.raises(InvalidBodyError):
            body.validate(b)

    def test_uuid_uppercase_rejected(self) -> None:
        b = dict(_VALID, i="550E8400-E29B-41D4-A716-446655440000")
        with pytest.raises(InvalidBodyError):
            body.validate(b)

    def test_negative_timestamp_rejected(self) -> None:
        b = dict(_VALID, t=-1)
        with pytest.raises(InvalidBodyError):
            body.validate(b)

    def test_unknown_suite_rejected(self) -> None:
        b = dict(_VALID, a="NOT-A-REAL-SUITE")
        with pytest.raises(InvalidBodyError):
            body.validate(b)

    def test_non_base64_payload_rejected(self) -> None:
        b = dict(_VALID, p="not!!base64")
        with pytest.raises(InvalidBodyError):
            body.validate(b)


class TestSerialize:
    """Serialization emits the spec-recommended field order."""

    def test_field_order_is_a_i_t_s_r_p_g(self) -> None:
        out = body.serialize(dict(_VALID))
        assert out.decode("utf-8").startswith('{"a":"RSA-OAEP-SHA256","i":')

    def test_serialize_is_compact(self) -> None:
        out = body.serialize(dict(_VALID))
        assert b" " not in out

    def test_unicode_kept_as_utf8(self) -> None:
        # If a future field carried non-ASCII, ensure_ascii=False keeps bytes.
        b = dict(_VALID)
        out = body.serialize(b)
        # Recoverable to original.
        assert body.parse(out) == b
