from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from plaincloak.exceptions import InvalidKeyError

_REQUIRED_PUBLIC_EXPONENT: int = 65537
_ALLOWED_MODULUS_BITS: frozenset[int] = frozenset({2048, 3072, 4096})

_PKCS1_PUBLIC_LABEL: bytes = b"-----BEGIN RSA PUBLIC KEY-----"
_PKCS1_PRIVATE_LABEL: bytes = b"-----BEGIN RSA PRIVATE KEY-----"


def _as_bytes(pem: str | bytes) -> bytes:
    """Return `pem` as bytes, encoding str input as UTF-8."""
    return pem.encode("utf-8") if isinstance(pem, str) else pem


def load_public_key(pem: str | bytes) -> RSAPublicKey:
    """Load an RSA public key from SPKI PEM.

    Args:
        pem (str | bytes): SPKI PEM (`BEGIN PUBLIC KEY`).

    Raises:
        InvalidKeyError: If the PEM uses the PKCS#1 label, is not parseable
            as SPKI, or is not an RSA key.

    Returns:
        RSAPublicKey: The loaded public key.
    """
    data = _as_bytes(pem)
    if _PKCS1_PUBLIC_LABEL in data:
        raise InvalidKeyError(
            "PKCS#1 'RSA PUBLIC KEY' PEM is not accepted; use SPKI "
            "'PUBLIC KEY' (RFC 5280 SubjectPublicKeyInfo)"
        )
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError(f"could not parse SPKI public key: {exc}") from exc
    if not isinstance(key, RSAPublicKey):
        raise InvalidKeyError("public key is not an RSA key")
    return key


def load_private_key(
    pem: str | bytes, password: bytes | None = None
) -> RSAPrivateKey:
    """Load an RSA private key from PKCS#8 PEM.

    Args:
        pem (str | bytes): PKCS#8 PEM (`BEGIN PRIVATE KEY` or
            `BEGIN ENCRYPTED PRIVATE KEY`).
        password (bytes | None): Decryption password for an encrypted
            PKCS#8 PEM. `None` for an unencrypted key.

    Raises:
        InvalidKeyError: If the PEM uses the PKCS#1 label, is not parseable
            as PKCS#8, or is not an RSA key.

    Returns:
        RSAPrivateKey: The loaded private key.
    """
    data = _as_bytes(pem)
    if _PKCS1_PRIVATE_LABEL in data:
        raise InvalidKeyError(
            "PKCS#1 'RSA PRIVATE KEY' PEM is not accepted; use PKCS#8 "
            "'PRIVATE KEY' (RFC 5958)"
        )
    try:
        key = serialization.load_pem_private_key(data, password=password)
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError(
            f"could not parse PKCS#8 private key: {exc}"
        ) from exc
    if not isinstance(key, RSAPrivateKey):
        raise InvalidKeyError("private key is not an RSA key")
    return key


def spki_der(public_key: RSAPublicKey) -> bytes:
    """Return the SubjectPublicKeyInfo DER bytes of an RSA public key.

    Args:
        public_key (RSAPublicKey): Key to encode.

    Returns:
        bytes: Strict DER SPKI encoding (RFC 5280 4.1.2.7).
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def key_hash(key: RSAPublicKey | RSAPrivateKey) -> str:
    """Return the 64-char lowercase hex SHA-256 of the SPKI DER.

    The hash is always computed over the public key's SPKI DER. A private
    key is routed through its public half so callers can pass either.

    Args:
        key (RSAPublicKey | RSAPrivateKey): Public or private RSA key.

    Returns:
        str: 64-character lowercase hex digest (spec section 9.2).
    """
    public = key.public_key() if isinstance(key, RSAPrivateKey) else key
    return hashlib.sha256(spki_der(public)).hexdigest()


def modulus_bytes(key: RSAPublicKey | RSAPrivateKey) -> int:
    """Return the RSA modulus length in bytes.

    Args:
        key (RSAPublicKey | RSAPrivateKey): RSA key.

    Returns:
        int: Modulus byte length (e.g. 256 for RSA-2048, 512 for RSA-4096).
    """
    return (key.key_size + 7) // 8


def check_rsa_modulus(key: RSAPublicKey | RSAPrivateKey) -> None:
    """Validate the modulus size and public exponent per spec section 8.2.

    Args:
        key (RSAPublicKey | RSAPrivateKey): RSA key to validate.

    Raises:
        InvalidKeyError: If `key_size` is not 2048/3072/4096 or the public
            exponent is not 65537.
    """
    if key.key_size not in _ALLOWED_MODULUS_BITS:
        raise InvalidKeyError(
            f"RSA modulus size {key.key_size} is not permitted; "
            f"v1 requires one of {sorted(_ALLOWED_MODULUS_BITS)}"
        )
    public = key.public_key() if isinstance(key, RSAPrivateKey) else key
    exponent = public.public_numbers().e
    if exponent != _REQUIRED_PUBLIC_EXPONENT:
        raise InvalidKeyError(
            f"RSA public exponent must be {_REQUIRED_PUBLIC_EXPONENT}; "
            f"got {exponent}"
        )


def generate_keypair(bits: int = 4096) -> RSAPrivateKey:
    """Generate a fresh RSA private key with the fixed public exponent.

    Args:
        bits (int): Modulus size in bits. MUST be 2048, 3072, or 4096.
            Defaults to 4096.

    Raises:
        InvalidKeyError: If `bits` is not a permitted modulus size.

    Returns:
        RSAPrivateKey: The generated private key. Its public half is
            obtained via `.public_key()`.
    """
    if bits not in _ALLOWED_MODULUS_BITS:
        raise InvalidKeyError(
            f"RSA modulus size {bits} is not permitted; "
            f"v1 requires one of {sorted(_ALLOWED_MODULUS_BITS)}"
        )
    return rsa.generate_private_key(
        public_exponent=_REQUIRED_PUBLIC_EXPONENT, key_size=bits
    )
