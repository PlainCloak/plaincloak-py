from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)


class Suite(str, Enum):
    """Cryptographic-suite identifiers as they appear in `body.suite`.

    Values are the exact spec strings; comparison against a wire body uses
    string equality, so callers may compare with raw strings as well.
    """

    RSA_OAEP_SHA256 = "RSA-OAEP-SHA256"
    RSA_OAEP_AES256GCM_SHA256 = "RSA-OAEP-AES256GCM-SHA256"


class Outcome(str, Enum):
    """The five consumer outcomes from spec section 10.3.

    These are never raised. They are surfaced as `DecryptResult.outcome` so
    consumers can deliver plaintext alongside a warning (`signature-invalid`
    or `unknown-sender`) as required by spec section 10.4.
    """

    VERIFIED = "verified"
    SIGNATURE_INVALID = "signature-invalid"
    UNKNOWN_SENDER = "unknown-sender"
    WRONG_RECIPIENT = "wrong-recipient"
    DECRYPTION_FAILED = "decryption-failed"


@dataclass(frozen=True, slots=True)
class KeyPair:
    """Bundle of an RSA private key, its public half, and the SPKI key hash.

    Attributes:
        private_key (RSAPrivateKey): The freshly generated private key.
        public_key (RSAPublicKey): Derived from `private_key.public_key()`.
        key_hash (str): Lowercase hex SHA-256 of the SubjectPublicKeyInfo DER.
    """

    private_key: RSAPrivateKey
    public_key: RSAPublicKey
    key_hash: str


@dataclass(frozen=True, slots=True)
class EnvelopeInfo:
    """Metadata extracted from a wire string without performing decryption.

    Attributes:
        suite (str): Value of `body.suite` (raw string from the body).
        message_id (str): UUIDv4 string from `body.id`.
        timestamp_ms (int): Producer timestamp from `body.ts`.
        sender_key_hash (str): Lowercase hex SHA-256 of sender SPKI.
        recipient_key_hash (str): Lowercase hex SHA-256 of recipient SPKI.
        payload_len (int): Length of the ciphertext payload in bytes.
        signature_len (int): Length of the signature in bytes.
        body_len (int): Length of the decompressed JSON body in bytes.
    """

    suite: str
    message_id: str
    timestamp_ms: int
    sender_key_hash: str
    recipient_key_hash: str
    payload_len: int
    signature_len: int
    body_len: int


@dataclass(frozen=True, slots=True)
class OwnKeyEntry:
    """Metadata for one of the user's own keypairs stored in the keystore.

    The private key is not included; retrieve it with
    `Keystore.decrypt_private_key`.

    Attributes:
        label (str): Human-readable name assigned at key generation time.
        key_hash (str): Lowercase hex SHA-256 of the SPKI DER (matches `key_hash()`).
        public_key (RSAPublicKey): The RSA public key, ready for `encrypt()`.
        created_at (int): Unix timestamp in milliseconds when the key was stored.
        expires_at (int | None): Optional key-rotation deadline (Unix ms), or None.
    """

    label: str
    key_hash: str
    public_key: RSAPublicKey
    created_at: int
    expires_at: int | None


@dataclass(frozen=True, slots=True)
class ContactEntry:
    """A trusted contact's public key stored in the keystore.

    Attributes:
        alias (str): Human-readable contact name.
        key_hash (str): Lowercase hex SHA-256 of the SPKI DER.
        public_key (RSAPublicKey): The RSA public key, ready for use in
            `trusted_senders`.
        added_at (int): Unix timestamp in milliseconds when the contact was added.
        verified_at (int | None): Time the key was confirmed out-of-band
            (Unix ms), or None.
        notes (str): Optional free-text notes.
    """

    alias: str
    key_hash: str
    public_key: RSAPublicKey
    added_at: int
    verified_at: int | None
    notes: str


@dataclass(frozen=True, slots=True)
class DecryptResult:
    """Outcome of `decrypt`, including plaintext when one was produced.

    Per spec section 10.4, `plaintext` is populated for `verified`,
    `signature-invalid`, and `unknown-sender`. It is `None` for
    `wrong-recipient` and `decryption-failed`.

    Attributes:
        outcome (Outcome): One of the five spec section 10.3 outcomes.
        plaintext (str | None): UTF-8 decoded plaintext, if produced.
        suite (str): Value of `body.suite`.
        message_id (str): UUIDv4 string from `body.id`.
        timestamp_ms (int): Producer timestamp from `body.ts`.
        sender_key_hash (str): Lowercase hex SHA-256 of sender SPKI.
        recipient_key_hash (str): Lowercase hex SHA-256 of recipient SPKI.
    """

    outcome: Outcome
    plaintext: str | None
    suite: str
    message_id: str
    timestamp_ms: int
    sender_key_hash: str
    recipient_key_hash: str
