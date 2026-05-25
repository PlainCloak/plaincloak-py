from __future__ import annotations

import plaincloak
from plaincloak import exceptions as exc
from plaincloak.types import (
    DecryptResult,
    EnvelopeInfo,
    KeyPair,
    Outcome,
    Suite,
)


class TestHierarchy:
    """Confirm every leaf exception inherits the expected ancestor."""

    def test_malformed_wire_subclasses_chain_to_base(self) -> None:
        for cls in (
            exc.UnsupportedVersionError,
            exc.UnknownCompressionError,
            exc.InvalidBase62Error,
            exc.DecompressionFailedError,
            exc.DecompressedTooLargeError,
            exc.InvalidJSONError,
            exc.InvalidBodyError,
            exc.UnknownSuiteError,
        ):
            assert issubclass(cls, exc.MalformedWireError)
            assert issubclass(cls, exc.PlainCloakError)

    def test_keystore_subclasses_chain_to_base(self) -> None:
        assert issubclass(exc.KeystoreLockedError, exc.KeystoreError)
        assert issubclass(exc.KeystoreFormatError, exc.KeystoreError)
        assert issubclass(exc.KeystoreError, exc.PlainCloakError)

    def test_producer_errors_are_plaincloak_errors(self) -> None:
        assert issubclass(exc.InvalidKeyError, exc.PlainCloakError)
        assert issubclass(exc.PlaintextTooLargeError, exc.PlainCloakError)

    def test_malformed_is_not_keystore(self) -> None:
        assert not issubclass(exc.MalformedWireError, exc.KeystoreError)
        assert not issubclass(exc.KeystoreError, exc.MalformedWireError)


class TestTypes:
    """Confirm the public enums and dataclasses behave as documented."""

    def test_suite_values_match_spec_strings(self) -> None:
        assert Suite.RSA_OAEP_SHA256.value == "RSA-OAEP-SHA256"
        assert Suite.RSA_OAEP_AES256GCM_SHA256.value == "RSA-OAEP-AES256GCM-SHA256"

    def test_outcome_values_match_spec_strings(self) -> None:
        assert Outcome.VERIFIED.value == "verified"
        assert Outcome.SIGNATURE_INVALID.value == "signature-invalid"
        assert Outcome.UNKNOWN_SENDER.value == "unknown-sender"
        assert Outcome.WRONG_RECIPIENT.value == "wrong-recipient"
        assert Outcome.DECRYPTION_FAILED.value == "decryption-failed"

    def test_envelope_info_is_frozen(self) -> None:
        info = EnvelopeInfo(
            suite="RSA-OAEP-SHA256",
            message_id="00000000-0000-4000-8000-000000000000",
            timestamp_ms=0,
            sender_key_hash="00" * 32,
            recipient_key_hash="11" * 32,
            payload_len=0,
            signature_len=0,
            body_len=0,
        )
        import dataclasses

        with __import__("pytest").raises(dataclasses.FrozenInstanceError):
            info.suite = "tampered"  # type: ignore[misc]

    def test_decrypt_result_allows_none_plaintext(self) -> None:
        result = DecryptResult(
            outcome=Outcome.WRONG_RECIPIENT,
            plaintext=None,
            suite="RSA-OAEP-SHA256",
            message_id="00000000-0000-4000-8000-000000000000",
            timestamp_ms=0,
            sender_key_hash="00" * 32,
            recipient_key_hash="11" * 32,
        )
        assert result.plaintext is None
        assert result.outcome is Outcome.WRONG_RECIPIENT


class TestPublicSurface:
    """Confirm the package re-exports the documented names."""

    def test_version_string(self) -> None:
        assert isinstance(plaincloak.__version__, str)
        assert plaincloak.__version__

    def test_reexports_present(self) -> None:
        expected = {
            "Suite",
            "Outcome",
            "KeyPair",
            "EnvelopeInfo",
            "DecryptResult",
            "PlainCloakError",
            "MalformedWireError",
            "UnsupportedVersionError",
            "UnknownCompressionError",
            "InvalidBase62Error",
            "DecompressionFailedError",
            "DecompressedTooLargeError",
            "InvalidJSONError",
            "InvalidBodyError",
            "UnknownSuiteError",
            "InvalidKeyError",
            "PlaintextTooLargeError",
            "KeystoreError",
            "KeystoreLockedError",
            "KeystoreFormatError",
        }
        for name in expected:
            assert hasattr(plaincloak, name), name

    def test_keypair_is_dataclass(self) -> None:
        # KeyPair fields exist with the documented names.
        fields = {f for f in KeyPair.__dataclass_fields__}
        assert fields == {"private_key", "public_key", "key_hash"}
