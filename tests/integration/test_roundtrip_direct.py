from __future__ import annotations

import pytest

from plaincloak.core import canonical, keys
from plaincloak.core.suites import base
from plaincloak.core.suites.rsa_oaep_sha256 import RsaOaepSha256Suite
from plaincloak.exceptions import PlaintextTooLargeError

SUITE = RsaOaepSha256Suite()


def _noop_aad() -> bytes:
    return b""


@pytest.mark.parametrize("bits", [2048, 4096])
def test_encrypt_decrypt_roundtrip(bits: int) -> None:
    recipient = keys.generate_keypair(bits=bits)
    plaintext = "héllo, wörld - direct suite".encode()

    payload = SUITE.encrypt_payload(
        plaintext,
        recipient_public_key=recipient.public_key(),
        aad_factory=_noop_aad,
    )
    assert len(payload) == keys.modulus_bytes(recipient)

    out = SUITE.decrypt_payload(
        payload,
        recipient_private_key=recipient,
        aad_factory=_noop_aad,
    )
    assert out == plaintext


def test_sign_verify_roundtrip() -> None:
    sender = keys.generate_keypair(bits=2048)
    c = canonical.build_canonical(
        wire_version_int=1,
        a="RSA-OAEP-SHA256",
        i="550e8400-e29b-41d4-a716-446655440000",
        t=1746789123456,
        s=keys.key_hash(sender),
        r="b" * 64,
        p="QQ==",
    )
    sig = base.sign(c, sender)
    assert base.verify(c, sig, sender.public_key()) is True


def test_tampered_canonical_fails_verify() -> None:
    sender = keys.generate_keypair(bits=2048)
    c = canonical.build_canonical(
        wire_version_int=1,
        a="RSA-OAEP-SHA256",
        i="550e8400-e29b-41d4-a716-446655440000",
        t=1,
        s="a" * 64,
        r="b" * 64,
        p="QQ==",
    )
    sig = base.sign(c, sender)
    tampered = c.replace(b":1:", b":2:", 1)
    assert base.verify(tampered, sig, sender.public_key()) is False


def test_wrong_key_size_payload_is_opaque_failure() -> None:
    recipient = keys.generate_keypair(bits=2048)
    with pytest.raises(base._DecryptionFailed):
        SUITE.decrypt_payload(
            b"\x00" * 10,
            recipient_private_key=recipient,
            aad_factory=_noop_aad,
        )


def test_max_plaintext_cap_is_modulus_minus_66() -> None:
    recipient = keys.generate_keypair(bits=2048)
    assert SUITE.max_plaintext_bytes(recipient.public_key()) == 256 - 66


def test_oversized_plaintext_would_be_rejected_by_cap() -> None:
    # The suite itself relies on the producer enforcing the cap; this asserts
    # the cap value so the M4 producer can trust it.
    recipient = keys.generate_keypair(bits=2048)
    cap = SUITE.max_plaintext_bytes(recipient.public_key())
    assert cap is not None
    too_long = b"x" * (cap + 1)
    # Encrypting beyond the cap raises from the primitive; the producer maps
    # this to PlaintextTooLargeError in M4. Here we just confirm it fails.
    with pytest.raises(ValueError):
        SUITE.encrypt_payload(
            too_long,
            recipient_public_key=recipient.public_key(),
            aad_factory=_noop_aad,
        )


def test_plaintext_too_large_error_is_importable() -> None:
    # M4 wiring sanity: the producer-side exception exists for the cap path.
    assert issubclass(PlaintextTooLargeError, Exception)
