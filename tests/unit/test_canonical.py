from __future__ import annotations

from plaincloak.core import canonical


class TestBuildCanonical:
    """Spec section 7.2 examples."""

    def test_worked_example_matches_spec(self) -> None:
        out = canonical.build_canonical(
            wire_version_int=1,
            a="RSA-OAEP-SHA256",
            i="550e8400-e29b-41d4-a716-446655440000",
            t=1746789123456,
            s="abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1",
            r="def456def456def456def456def456def456def456def456def456def456def4",
            p="TmluZXR5IG5pbmU=",
        )
        expected = (
            b"1:RSA-OAEP-SHA256:550e8400-e29b-41d4-a716-446655440000:"
            b"1746789123456:"
            b"abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1:"
            b"def456def456def456def456def456def456def456def456def456def456def4:"
            b"TmluZXR5IG5pbmU="
        )
        assert out == expected

    def test_zero_timestamp_serializes_as_literal_zero(self) -> None:
        out = canonical.build_canonical(
            wire_version_int=1,
            a="RSA-OAEP-SHA256",
            i="00000000-0000-4000-8000-000000000000",
            t=0,
            s="0" * 64,
            r="f" * 64,
            p="",
        )
        assert out.endswith(b":0:" + (b"0" * 64) + b":" + (b"f" * 64) + b":")

    def test_returns_bytes_not_str(self) -> None:
        out = canonical.build_canonical(
            wire_version_int=1,
            a="RSA-OAEP-SHA256",
            i="00000000-0000-4000-8000-000000000000",
            t=0,
            s="0" * 64,
            r="f" * 64,
            p="QQ==",
        )
        assert isinstance(out, bytes)


class TestBuildAAD:
    """`build_aad` matches canonical form with empty `p` segment."""

    def test_aad_has_trailing_colon_with_empty_p(self) -> None:
        aad = canonical.build_aad(
            wire_version_int=1,
            a="RSA-OAEP-AES256GCM-SHA256",
            i="11111111-2222-4333-8444-555555555555",
            t=42,
            s="1" * 64,
            r="2" * 64,
        )
        assert aad.endswith(b":")
        assert aad.count(b":") == 6

    def test_aad_equals_canonical_with_blank_p(self) -> None:
        kwargs = dict(
            wire_version_int=1,
            a="RSA-OAEP-AES256GCM-SHA256",
            i="11111111-2222-4333-8444-555555555555",
            t=42,
            s="1" * 64,
            r="2" * 64,
        )
        assert canonical.build_aad(**kwargs) == canonical.build_canonical(
            **kwargs, p=""
        )
