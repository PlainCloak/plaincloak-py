from __future__ import annotations

import abc
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from plaincloak.core import keys

_PSS_SALT_LENGTH: int = 32


class _DecryptionFailed(Exception):
    """Internal opaque sentinel for any consumer-side crypto failure.

    Carries no message and no sub-cause. `api.decrypt` catches it and maps
    it to the `decryption-failed` outcome. Never surfaced to callers.
    """


def _pss_padding() -> padding.PSS:
    """Return the fixed RSA-PSS padding (MGF1-SHA-256, 32-byte salt)."""
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=_PSS_SALT_LENGTH,
    )


def sign(canonical_bytes: bytes, sender_private_key: RSAPrivateKey) -> bytes:
    """Sign the canonical-form bytes with RSA-PSS-SHA256.

    Args:
        canonical_bytes (bytes): Output of `core.canonical.build_canonical`.
        sender_private_key (RSAPrivateKey): Sender's signing key.

    Returns:
        bytes: PSS signature, length equal to the sender modulus byte length.
    """
    return sender_private_key.sign(
        canonical_bytes, _pss_padding(), hashes.SHA256()
    )


def verify(
    canonical_bytes: bytes,
    signature: bytes,
    sender_public_key: RSAPublicKey,
) -> bool:
    """Verify an RSA-PSS-SHA256 signature over the canonical form.

    A length mismatch between `signature` and the sender modulus is treated
    as an invalid signature (spec section 8.7 step 3), not an exception.

    Args:
        canonical_bytes (bytes): Reconstructed canonical-form bytes.
        signature (bytes): Decoded `g` field bytes.
        sender_public_key (RSAPublicKey): Sender's verification key.

    Returns:
        bool: True only if the signature is valid for this key and message.
    """
    if len(signature) != keys.modulus_bytes(sender_public_key):
        return False
    try:
        sender_public_key.verify(
            signature, canonical_bytes, _pss_padding(), hashes.SHA256()
        )
    except InvalidSignature:
        return False
    return True


class Suite(abc.ABC):
    """Abstract cryptographic suite: payload encryption and shape checks.

    The signing component is shared (module-level `sign`/`verify`); only the
    `p`-field encryption differs between the direct and hybrid suites.
    """

    #: The body `a` identifier this suite implements.
    identifier: str

    @abc.abstractmethod
    def encrypt_payload(
        self,
        plaintext: bytes,
        *,
        recipient_public_key: RSAPublicKey,
        aad_factory: Callable[[], bytes],
    ) -> bytes:
        """Encrypt `plaintext` into the decoded `p`-field bytes.

        Args:
            plaintext (bytes): UTF-8, NFC-normalized plaintext (the producer
                does the normalization upstream).
            recipient_public_key (RSAPublicKey): Recipient encryption key.
            aad_factory (Callable[[], bytes]): Zero-arg callable returning
                the AAD bytes for suites that need it (hybrid). Ignored by
                the direct suite.

        Returns:
            bytes: Raw payload bytes to Base64-encode into `p`.
        """

    @abc.abstractmethod
    def decrypt_payload(
        self,
        payload: bytes,
        *,
        recipient_private_key: RSAPrivateKey,
        aad_factory: Callable[[], bytes],
    ) -> bytes:
        """Decrypt decoded `p`-field bytes back to UTF-8 plaintext bytes.

        Args:
            payload (bytes): Base64-decoded `p` bytes.
            recipient_private_key (RSAPrivateKey): Matched private key.
            aad_factory (Callable[[], bytes]): Zero-arg callable returning
                the AAD bytes for suites that need it (hybrid). Ignored by
                the direct suite.

        Raises:
            _DecryptionFailed: For every failure mode, with no sub-cause.

        Returns:
            bytes: Decrypted plaintext bytes (caller decodes UTF-8).
        """

    @abc.abstractmethod
    def max_plaintext_bytes(self, recipient_public_key: RSAPublicKey) -> int | None:
        """Return the producer-side plaintext cap, or None if uncapped.

        Args:
            recipient_public_key (RSAPublicKey): Recipient key (the direct
                suite's cap depends on its modulus).

        Returns:
            int | None: Maximum plaintext length in bytes, or None when the
                suite imposes no per-key cap (hybrid).
        """
