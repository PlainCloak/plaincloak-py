from __future__ import annotations

import base64

import pytest

import plaincloak
from plaincloak import (
    Outcome,
    Suite,
    decrypt,
    encrypt,
    generate_keypair,
    parse_envelope,
)
from plaincloak.core import base62, body, compression
from plaincloak.exceptions import PlaintextTooLargeError


@pytest.fixture(scope="module")
def alice() -> plaincloak.KeyPair:
    return generate_keypair(bits=2048)


@pytest.fixture(scope="module")
def bob() -> plaincloak.KeyPair:
    return generate_keypair(bits=2048)


@pytest.fixture(scope="module")
def mallory() -> plaincloak.KeyPair:
    return generate_keypair(bits=2048)


class TestVerified:
    """Sender trusted, signature valid -> verified, plaintext present."""

    @pytest.mark.parametrize(
        "suite", [Suite.RSA_OAEP_SHA256, Suite.RSA_OAEP_AES256GCM_SHA256]
    )
    def test_verified_both_suites(
        self,
        alice: plaincloak.KeyPair,
        bob: plaincloak.KeyPair,
        suite: Suite,
    ) -> None:
        wire = encrypt(
            "hello bob",
            recipient_public_key=bob.public_key,
            sender_private_key=alice.private_key,
            suite=suite,
        )
        result = decrypt(
            wire,
            own_private_keys=[bob.private_key],
            trusted_senders={alice.key_hash: alice.public_key},
        )
        assert result.outcome is Outcome.VERIFIED
        assert result.plaintext == "hello bob"
        assert result.sender_key_hash == alice.key_hash
        assert result.recipient_key_hash == bob.key_hash


class TestUnknownSender:
    """Sender not in contacts -> unknown-sender, plaintext still present."""

    def test_unknown_sender_carries_plaintext(
        self, alice: plaincloak.KeyPair, bob: plaincloak.KeyPair
    ) -> None:
        wire = encrypt(
            "anonymous tip",
            recipient_public_key=bob.public_key,
            sender_private_key=alice.private_key,
        )
        result = decrypt(wire, own_private_keys=[bob.private_key])
        assert result.outcome is Outcome.UNKNOWN_SENDER
        assert result.plaintext == "anonymous tip"


class TestWrongRecipient:
    """No matching private key -> wrong-recipient, no plaintext."""

    def test_wrong_recipient_no_plaintext(
        self,
        alice: plaincloak.KeyPair,
        bob: plaincloak.KeyPair,
        mallory: plaincloak.KeyPair,
    ) -> None:
        wire = encrypt(
            "for bob only",
            recipient_public_key=bob.public_key,
            sender_private_key=alice.private_key,
        )
        result = decrypt(wire, own_private_keys=[mallory.private_key])
        assert result.outcome is Outcome.WRONG_RECIPIENT
        assert result.plaintext is None


class TestSignatureInvalid:
    """Trusted sender but tampered canonical input -> signature-invalid.

    The plaintext is still delivered (spec section 10.4). Tampering the `t`
    field after signing breaks the signature without breaking decryption,
    because `g` covers the canonical form which includes `t`.
    """

    def test_signature_invalid_carries_plaintext(
        self, alice: plaincloak.KeyPair, bob: plaincloak.KeyPair
    ) -> None:
        wire = encrypt(
            "tamper me",
            recipient_public_key=bob.public_key,
            sender_private_key=alice.private_key,
            suite=Suite.RSA_OAEP_SHA256,
            timestamp_ms=1000,
        )
        # Rebuild the wire with a mutated `t` so `g` no longer matches.
        parsed_bytes = compression.decompress(
            base62.decode(wire.split(":", 3)[3]), code="BR"
        )
        msg = body.parse(parsed_bytes)
        msg["t"] = 2000
        tampered = compression.compress(body.serialize(msg), code="BR")
        tampered_wire = f"PLAINCLOAK:v1:BR:{base62.encode(tampered)}"

        result = decrypt(
            tampered_wire,
            own_private_keys=[bob.private_key],
            trusted_senders={alice.key_hash: alice.public_key},
        )
        assert result.outcome is Outcome.SIGNATURE_INVALID
        assert result.plaintext == "tamper me"


class TestDecryptionFailed:
    """Tampered payload -> decryption-failed, no plaintext, opaque."""

    def test_decryption_failed_no_plaintext(
        self, alice: plaincloak.KeyPair, bob: plaincloak.KeyPair
    ) -> None:
        wire = encrypt(
            "secret",
            recipient_public_key=bob.public_key,
            sender_private_key=alice.private_key,
            suite=Suite.RSA_OAEP_AES256GCM_SHA256,
        )
        raw = compression.decompress(
            base62.decode(wire.split(":", 3)[3]), code="BR"
        )
        msg = body.parse(raw)
        payload = bytearray(base64.b64decode(msg["p"]))
        payload[-1] ^= 0xFF  # corrupt the AEAD tag
        msg["p"] = base64.b64encode(bytes(payload)).decode("ascii")
        broken = compression.compress(body.serialize(msg), code="BR")
        broken_wire = f"PLAINCLOAK:v1:BR:{base62.encode(broken)}"

        result = decrypt(
            broken_wire,
            own_private_keys=[bob.private_key],
            trusted_senders={alice.key_hash: alice.public_key},
        )
        assert result.outcome is Outcome.DECRYPTION_FAILED
        assert result.plaintext is None


class TestProducerGuards:
    """Producer-side caps and key index behavior."""

    def test_direct_suite_rejects_oversized_plaintext(
        self, alice: plaincloak.KeyPair, bob: plaincloak.KeyPair
    ) -> None:
        # RSA-2048 direct cap is 190 bytes.
        with pytest.raises(PlaintextTooLargeError):
            encrypt(
                "x" * 200,
                recipient_public_key=bob.public_key,
                sender_private_key=alice.private_key,
                suite=Suite.RSA_OAEP_SHA256,
            )

    def test_hybrid_suite_accepts_long_plaintext(
        self, alice: plaincloak.KeyPair, bob: plaincloak.KeyPair
    ) -> None:
        wire = encrypt(
            "y" * 5000,
            recipient_public_key=bob.public_key,
            sender_private_key=alice.private_key,
            suite=Suite.RSA_OAEP_AES256GCM_SHA256,
        )
        result = decrypt(
            wire,
            own_private_keys=[bob.private_key],
            trusted_senders={alice.key_hash: alice.public_key},
        )
        assert result.outcome is Outcome.VERIFIED
        assert result.plaintext == "y" * 5000

    def test_decrypt_accepts_mapping_keystore(
        self, alice: plaincloak.KeyPair, bob: plaincloak.KeyPair
    ) -> None:
        wire = encrypt(
            "mapped",
            recipient_public_key=bob.public_key,
            sender_private_key=alice.private_key,
        )
        result = decrypt(
            wire,
            own_private_keys={bob.key_hash: bob.private_key},
            trusted_senders={alice.key_hash: alice.public_key},
        )
        assert result.outcome is Outcome.VERIFIED


class TestParseEnvelope:
    """`parse_envelope` returns metadata without any key material."""

    def test_metadata_without_keys(
        self, alice: plaincloak.KeyPair, bob: plaincloak.KeyPair
    ) -> None:
        wire = encrypt(
            "inspect me",
            recipient_public_key=bob.public_key,
            sender_private_key=alice.private_key,
            suite=Suite.RSA_OAEP_AES256GCM_SHA256,
            message_id="b5ca2440-fbb0-4e33-83af-4222bf2b0bf5",
            timestamp_ms=1746789123456,
        )
        info = parse_envelope(wire)
        assert info.suite == "RSA-OAEP-AES256GCM-SHA256"
        assert info.message_id == "b5ca2440-fbb0-4e33-83af-4222bf2b0bf5"
        assert info.timestamp_ms == 1746789123456
        assert info.sender_key_hash == alice.key_hash
        assert info.recipient_key_hash == bob.key_hash
        assert info.payload_len > 0
        assert info.signature_len == 256  # RSA-2048 PSS signature
        assert info.body_len > 0
