from __future__ import annotations

import base64
import json

import pytest

from plaincloak import api
from plaincloak.core import base62, compression, keys
from plaincloak.exceptions import (
    DecompressedTooLargeError,
    InvalidBodyError,
    UnknownCompressionError,
)
from plaincloak.types import Outcome
from tests.conftest import PEMKey


def _valid_body_json(*, p_bytes: int = 16) -> bytes:
    """A schema-valid body whose `p` decodes to `p_bytes` bytes."""
    body = {
        "a": "RSA-OAEP-SHA256",
        "i": "550e8400-e29b-41d4-a716-446655440000",
        "t": 0,
        "s": "0" * 64,
        "r": "f" * 64,
        "p": base64.b64encode(b"\x01" * p_bytes).decode("ascii"),
        "g": "QUJDRA==",
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def _no_wire(body_bytes: bytes) -> str:
    """Assemble an identity-compressed wire directly (producers may not)."""
    return f"PLAINCLOAK:v1:NO:{base62.encode(body_bytes)}"


def _br_wire(body_bytes: bytes) -> str:
    return (
        f"PLAINCLOAK:v1:BR:"
        f"{base62.encode(compression.compress(body_bytes, code='BR'))}"
    )


class TestIdentityCompressionPolicy:
    """`decrypt` refuses `NO` by default; `parse_envelope` allows it."""

    def test_decrypt_refuses_no_by_default(self) -> None:
        with pytest.raises(UnknownCompressionError, match="diagnostic"):
            api.decrypt(_no_wire(_valid_body_json()), own_private_keys=[])

    def test_decrypt_accepts_no_when_enabled(self) -> None:
        result = api.decrypt(
            _no_wire(_valid_body_json()),
            own_private_keys=[],
            allow_identity_compression=True,
        )
        assert result.outcome is Outcome.WRONG_RECIPIENT

    def test_parse_envelope_accepts_no(self) -> None:
        info = api.parse_envelope(_no_wire(_valid_body_json()))
        assert info.suite == "RSA-OAEP-SHA256"


class TestBodySizeCap:
    """`decrypt` rejects decompressed bodies over the 64 KiB limit."""

    def test_oversized_body_rejected(self) -> None:
        body_bytes = _valid_body_json(p_bytes=80 * 1024)
        assert len(body_bytes) > 64 * 1024
        with pytest.raises(InvalidBodyError, match="64|practical"):
            api.decrypt(_br_wire(body_bytes), own_private_keys=[])

    def test_normal_body_unaffected(self) -> None:
        result = api.decrypt(
            _br_wire(_valid_body_json()), own_private_keys=[]
        )
        assert result.outcome is Outcome.WRONG_RECIPIENT


class TestConfigurableBodyLimit:
    """Both ends can raise `max_body_bytes` for large-payload deployments."""

    def test_large_payload_roundtrip_with_raised_limits(
        self, alice_pem: PEMKey, bob_pem: PEMKey
    ) -> None:
        plaintext = "x" * (100 * 1024)
        wire = api.encrypt(
            plaintext,
            recipient_public_key=keys.load_public_key(alice_pem.public_pem),
            sender_private_key=keys.load_private_key(bob_pem.private_pem),
            max_body_bytes=256 * 1024,
        )
        result = api.decrypt(
            wire,
            own_private_keys=[keys.load_private_key(alice_pem.private_pem)],
            max_body_bytes=256 * 1024,
        )
        assert result.plaintext == plaintext

    def test_default_producer_limit_refuses_large_payload(
        self, alice_pem: PEMKey, bob_pem: PEMKey
    ) -> None:
        from plaincloak.exceptions import PlaintextTooLargeError

        with pytest.raises(PlaintextTooLargeError):
            api.encrypt(
                "x" * (100 * 1024),
                recipient_public_key=keys.load_public_key(
                    alice_pem.public_pem
                ),
                sender_private_key=keys.load_private_key(
                    bob_pem.private_pem
                ),
            )


class TestWireTrailingWhitespace:
    """End-to-end: a pasted wire with a trailing newline decrypts."""

    def test_decrypt_tolerates_trailing_newline(
        self, alice_pem: PEMKey, bob_pem: PEMKey
    ) -> None:
        alice_priv = keys.load_private_key(alice_pem.private_pem)
        wire = api.encrypt(
            "hello",
            recipient_public_key=keys.load_public_key(alice_pem.public_pem),
            sender_private_key=keys.load_private_key(bob_pem.private_pem),
        )
        result = api.decrypt(wire + "\r\n", own_private_keys=[alice_priv])
        assert result.plaintext == "hello"


class TestParseEnvelopeBudget:
    """`parse_envelope` honors a caller-supplied decompression budget."""

    def test_budget_enforced(self) -> None:
        body_bytes = _valid_body_json(p_bytes=8 * 1024)
        with pytest.raises(DecompressedTooLargeError):
            api.parse_envelope(
                _br_wire(body_bytes), decompress_budget_bytes=1_024
            )
