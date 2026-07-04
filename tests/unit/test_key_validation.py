from __future__ import annotations

import base64
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from plaincloak import api
from plaincloak.core import body, canonical, compression, keys
from plaincloak.core.constants import WIRE_VERSION_INT
from plaincloak.core.envelope import format_envelope
from plaincloak.core.suites import base as suite_base
from plaincloak.core.suites import get_suite
from plaincloak.exceptions import InvalidKeyError
from plaincloak.types import Outcome
from tests.conftest import PEMKey


@pytest.fixture(scope="module")
def rsa1024() -> RSAPrivateKey:
    """A forbidden 1024-bit key, built directly to bypass the library."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


@pytest.fixture(scope="module")
def rsa2048_e3() -> RSAPrivateKey:
    """A 2048-bit key with the forbidden public exponent 3."""
    return rsa.generate_private_key(public_exponent=3, key_size=2048)


def _private_pem(key: RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_pem(key: RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _build_wire(
    recipient_public_key: RSAPublicKey, sender_private_key: RSAPrivateKey
) -> str:
    """Assemble a direct-suite wire via core internals, skipping the
    producer key checks so a message can address a forbidden key."""
    a = "RSA-OAEP-SHA256"
    i = str(uuid.uuid4())
    t = 0
    s = keys.key_hash(sender_private_key)
    r = keys.key_hash(recipient_public_key)
    payload = get_suite(a).encrypt_payload(
        b"hi",
        recipient_public_key=recipient_public_key,
        aad_factory=lambda: b"",
    )
    p = base64.b64encode(payload).decode("ascii")
    canonical_bytes = canonical.build_canonical(
        wire_version_int=WIRE_VERSION_INT, a=a, i=i, t=t, s=s, r=r, p=p
    )
    g = base64.b64encode(
        suite_base.sign(canonical_bytes, sender_private_key)
    ).decode("ascii")
    serialized = body.serialize(
        {"a": a, "i": i, "t": t, "s": s, "r": r, "p": p, "g": g}
    )
    return format_envelope(
        comp_code="BR", payload_bytes=compression.compress(serialized)
    )


class TestLoaderRejection:
    """PEM loaders enforce the spec section 8.2 key rules."""

    def test_public_loader_rejects_small_modulus(
        self, rsa1024: RSAPrivateKey
    ) -> None:
        with pytest.raises(InvalidKeyError, match="modulus"):
            keys.load_public_key(_public_pem(rsa1024))

    def test_private_loader_rejects_small_modulus(
        self, rsa1024: RSAPrivateKey
    ) -> None:
        with pytest.raises(InvalidKeyError, match="modulus"):
            keys.load_private_key(_private_pem(rsa1024))

    def test_public_loader_rejects_bad_exponent(
        self, rsa2048_e3: RSAPrivateKey
    ) -> None:
        with pytest.raises(InvalidKeyError, match="exponent"):
            keys.load_public_key(_public_pem(rsa2048_e3))

    def test_private_loader_rejects_bad_exponent(
        self, rsa2048_e3: RSAPrivateKey
    ) -> None:
        with pytest.raises(InvalidKeyError, match="exponent"):
            keys.load_private_key(_private_pem(rsa2048_e3))


class TestDecryptKeyValidation:
    """`decrypt` rejects forbidden keys it actually consults (matched via
    the body's `r` or `s` field); unmatched keys are the loaders' problem."""

    @pytest.fixture()
    def wire(self, alice_pem: PEMKey, bob_pem: PEMKey) -> str:
        """A valid bob -> alice wire message from the spec fixture keys."""
        return api.encrypt(
            "hello",
            recipient_public_key=keys.load_public_key(alice_pem.public_pem),
            sender_private_key=keys.load_private_key(bob_pem.private_pem),
        )

    def test_matched_forbidden_recipient_key_rejected(
        self, alice_pem: PEMKey, rsa1024: RSAPrivateKey
    ) -> None:
        wire = _build_wire(
            rsa1024.public_key(),
            keys.load_private_key(alice_pem.private_pem),
        )
        with pytest.raises(InvalidKeyError):
            api.decrypt(wire, own_private_keys=[rsa1024])

    def test_matched_forbidden_sender_key_rejected(
        self, wire: str, alice_pem: PEMKey, bob_pem: PEMKey, rsa1024: RSAPrivateKey
    ) -> None:
        bob_hash = keys.key_hash(keys.load_public_key(bob_pem.public_pem))
        with pytest.raises(InvalidKeyError):
            api.decrypt(
                wire,
                own_private_keys=[
                    keys.load_private_key(alice_pem.private_pem)
                ],
                trusted_senders={bob_hash: rsa1024.public_key()},
            )

    def test_unmatched_forbidden_key_does_not_block(
        self, wire: str, alice_pem: PEMKey, rsa1024: RSAPrivateKey
    ) -> None:
        own = [keys.load_private_key(alice_pem.private_pem), rsa1024]
        result = api.decrypt(wire, own_private_keys=own)
        assert result.outcome is Outcome.UNKNOWN_SENDER
        assert result.plaintext == "hello"

    def test_valid_keys_still_decrypt(
        self, wire: str, alice_pem: PEMKey
    ) -> None:
        result = api.decrypt(
            wire,
            own_private_keys=[keys.load_private_key(alice_pem.private_pem)],
        )
        assert result.plaintext == "hello"
