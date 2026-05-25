from __future__ import annotations

from collections.abc import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from plaincloak.core import keys
from plaincloak.core.suites.base import Suite, _DecryptionFailed

_OAEP_OVERHEAD: int = 2 + 2 * 32  # 66 bytes for SHA-256


def _oaep_padding() -> padding.OAEP:
    """Return the fixed RSA-OAEP padding (SHA-256, MGF1-SHA-256, empty label)."""
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


class RsaOaepSha256Suite(Suite):
    """RSA-OAEP-SHA256 direct encryption."""

    identifier = "RSA-OAEP-SHA256"

    def encrypt_payload(
        self,
        plaintext: bytes,
        *,
        recipient_public_key: RSAPublicKey,
        aad_factory: Callable[[], bytes],
    ) -> bytes:
        """RSA-OAEP-encrypt the plaintext. `aad_factory` is unused here."""
        return recipient_public_key.encrypt(plaintext, _oaep_padding())

    def decrypt_payload(
        self,
        payload: bytes,
        *,
        recipient_private_key: RSAPrivateKey,
        aad_factory: Callable[[], bytes],
    ) -> bytes:
        """RSA-OAEP-decrypt the payload.

        A length mismatch against the modulus (spec 8.5 step 3) and any OAEP
        padding error both collapse into `_DecryptionFailed` with no
        distinguishing message.
        """
        if len(payload) != keys.modulus_bytes(recipient_private_key):
            raise _DecryptionFailed
        try:
            return recipient_private_key.decrypt(payload, _oaep_padding())
        except ValueError as exc:
            raise _DecryptionFailed from exc

    def max_plaintext_bytes(self, recipient_public_key: RSAPublicKey) -> int | None:
        """Return `modulus_bytes - 66`, the RSA-OAEP-SHA256 plaintext cap."""
        return keys.modulus_bytes(recipient_public_key) - _OAEP_OVERHEAD
