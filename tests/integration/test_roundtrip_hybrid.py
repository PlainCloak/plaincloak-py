from __future__ import annotations

import pytest

from plaincloak.core import canonical, keys
from plaincloak.core.suites.base import _DecryptionFailed
from plaincloak.core.suites.rsa_oaep_aes256gcm_sha256 import (
    RsaOaepAes256GcmSha256Suite,
)

SUITE = RsaOaepAes256GcmSha256Suite()

_AAD = canonical.build_aad(
    wire_version_int=1,
    a="RSA-OAEP-AES256GCM-SHA256",
    i="b5ca2440-fbb0-4e33-83af-4222bf2b0bf5",
    t=1746789123456,
    s="b3cef20ec636c4125ae580da93dc0f13bdcdb1c3eea907543ed35ad52e024aee",
    r="1bf44bedd390cd114d5511c53286330f29c9fe70a4ab86118731860898ef88da",
)


def _aad() -> bytes:
    return _AAD


@pytest.mark.parametrize("bits", [2048, 4096])
def test_hybrid_roundtrip(bits: int) -> None:
    recipient = keys.generate_keypair(bits=bits)
    plaintext = "hybrid suite - unicode ✓".encode()

    payload = SUITE.encrypt_payload(
        plaintext,
        recipient_public_key=recipient.public_key(),
        aad_factory=_aad,
    )
    modulus_len = keys.modulus_bytes(recipient)
    # wrapped_K (M) || nonce (12) || ct (len pt) || tag (16)
    assert len(payload) == modulus_len + 12 + len(plaintext) + 16

    out = SUITE.decrypt_payload(
        payload,
        recipient_private_key=recipient,
        aad_factory=_aad,
    )
    assert out == plaintext


def test_hybrid_2kb_plaintext_roundtrips_on_2048_key() -> None:
    # The direct suite's n-66 cap (190 bytes for RSA-2048) does not apply.
    recipient = keys.generate_keypair(bits=2048)
    plaintext = ("A" * 2048).encode("utf-8")

    payload = SUITE.encrypt_payload(
        plaintext,
        recipient_public_key=recipient.public_key(),
        aad_factory=_aad,
    )
    out = SUITE.decrypt_payload(
        payload,
        recipient_private_key=recipient,
        aad_factory=_aad,
    )
    assert out == plaintext
    assert SUITE.max_plaintext_bytes(recipient.public_key()) is None


def test_tampered_tag_is_opaque_failure() -> None:
    recipient = keys.generate_keypair(bits=2048)
    payload = bytearray(
        SUITE.encrypt_payload(
            b"secret",
            recipient_public_key=recipient.public_key(),
            aad_factory=_aad,
        )
    )
    payload[-1] ^= 0xFF  # flip a tag byte
    with pytest.raises(_DecryptionFailed):
        SUITE.decrypt_payload(
            bytes(payload),
            recipient_private_key=recipient,
            aad_factory=_aad,
        )


def test_wrong_aad_is_opaque_failure() -> None:
    recipient = keys.generate_keypair(bits=2048)
    payload = SUITE.encrypt_payload(
        b"secret",
        recipient_public_key=recipient.public_key(),
        aad_factory=_aad,
    )
    with pytest.raises(_DecryptionFailed):
        SUITE.decrypt_payload(
            payload,
            recipient_private_key=recipient,
            aad_factory=lambda: b"different aad",
        )


def test_short_payload_is_opaque_failure() -> None:
    recipient = keys.generate_keypair(bits=2048)
    with pytest.raises(_DecryptionFailed):
        SUITE.decrypt_payload(
            b"\x00" * 10,
            recipient_private_key=recipient,
            aad_factory=_aad,
        )


def test_wrong_recipient_key_is_opaque_failure() -> None:
    recipient = keys.generate_keypair(bits=2048)
    other = keys.generate_keypair(bits=2048)
    payload = SUITE.encrypt_payload(
        b"secret",
        recipient_public_key=recipient.public_key(),
        aad_factory=_aad,
    )
    with pytest.raises(_DecryptionFailed):
        SUITE.decrypt_payload(
            payload,
            recipient_private_key=other,
            aad_factory=_aad,
        )
