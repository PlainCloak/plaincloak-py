from __future__ import annotations

import os
from collections.abc import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from plaincloak.core import keys
from plaincloak.core.suites.base import Suite, _DecryptionFailed

_AES_KEY_LEN: int = 32
_NONCE_LEN: int = 12
_TAG_LEN: int = 16


def _oaep_padding() -> padding.OAEP:
    """Return the fixed RSA-OAEP padding (SHA-256, MGF1-SHA-256, empty label)."""
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


class RsaOaepAes256GcmSha256Suite(Suite):
    """RSA-OAEP-wrapped AES-256-GCM hybrid encryption."""

    identifier = "RSA-OAEP-AES256GCM-SHA256"

    def encrypt_payload(
        self,
        plaintext: bytes,
        *,
        recipient_public_key: RSAPublicKey,
        aad_factory: Callable[[], bytes],
    ) -> bytes:
        """Wrap a fresh AES key, AES-256-GCM the plaintext, frame `p`.

        The framed bytes are `wrapped_K || nonce || ct || tag`; `cryptography`
        appends the 16-byte tag to the ciphertext, matching the spec layout.
        """
        symmetric_key = os.urandom(_AES_KEY_LEN)
        nonce = os.urandom(_NONCE_LEN)
        wrapped_key = recipient_public_key.encrypt(
            symmetric_key, _oaep_padding()
        )
        ct_and_tag = AESGCM(symmetric_key).encrypt(
            nonce, plaintext, aad_factory()
        )
        return wrapped_key + nonce + ct_and_tag

    def decrypt_payload(
        self,
        payload: bytes,
        *,
        recipient_private_key: RSAPrivateKey,
        aad_factory: Callable[[], bytes],
    ) -> bytes:
        """Reverse the framing and decrypt. All failures are opaque.

        Spec 8.10.5: reject short payloads, OAEP failure, wrapped-key length
        != 32, and AEAD tag failure - all as the single `_DecryptionFailed`.
        """
        modulus_len = keys.modulus_bytes(recipient_private_key)
        if len(payload) < modulus_len + _NONCE_LEN + _TAG_LEN:
            raise _DecryptionFailed

        wrapped_key = payload[:modulus_len]
        nonce = payload[modulus_len : modulus_len + _NONCE_LEN]
        ct_and_tag = payload[modulus_len + _NONCE_LEN :]

        try:
            symmetric_key = recipient_private_key.decrypt(
                wrapped_key, _oaep_padding()
            )
        except ValueError as exc:
            raise _DecryptionFailed from exc

        if len(symmetric_key) != _AES_KEY_LEN:
            raise _DecryptionFailed

        try:
            return AESGCM(symmetric_key).decrypt(
                nonce, ct_and_tag, aad_factory()
            )
        except InvalidTag as exc:
            raise _DecryptionFailed from exc

    def max_plaintext_bytes(self, recipient_public_key: RSAPublicKey) -> int | None:
        """Return None: the hybrid suite imposes no per-key plaintext cap."""
        return None
