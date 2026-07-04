from __future__ import annotations

import base64
import binascii
import time
import unicodedata
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from plaincloak.core import body, canonical, compression, keys
from plaincloak.core import qr as _qr
from plaincloak.core.constants import DEFAULT_DECOMPRESS_BUDGET, WIRE_VERSION_INT
from plaincloak.core.envelope import format_envelope
from plaincloak.core.envelope import parse_envelope as _parse_wire
from plaincloak.core.suites import base as suite_base
from plaincloak.core.suites import get_suite
from plaincloak.exceptions import InvalidBodyError, PlaintextTooLargeError
from plaincloak.types import (
    DecryptResult,
    EnvelopeInfo,
    KeyPair,
    Outcome,
    Suite,
)

if TYPE_CHECKING:
    from PIL.Image import Image as QRImage

_BODY_SIZE_LIMIT: int = 64 * 1024  # spec section 6.5 practical cap


def generate_keypair(bits: int = 4096) -> KeyPair:
    """Generate a fresh RSA keypair and its SPKI key hash.

    Args:
        bits (int): Modulus size in bits (2048, 3072, or 4096).
            Defaults to 4096.

    Raises:
        InvalidKeyError: If `bits` is not a permitted modulus size.

    Returns:
        KeyPair: Frozen bundle of private key, public key, and key hash.
    """
    private_key = keys.generate_keypair(bits=bits)
    public_key = private_key.public_key()
    return KeyPair(
        private_key=private_key,
        public_key=public_key,
        key_hash=keys.key_hash(public_key),
    )


def load_public_key_pem(pem: str | bytes) -> RSAPublicKey:
    """Load an RSA public key from SPKI PEM.

    Args:
        pem (str | bytes): SPKI `PUBLIC KEY` PEM.

    Raises:
        InvalidKeyError: If the PEM is PKCS#1, unparseable, or not RSA.

    Returns:
        RSAPublicKey: The loaded public key.
    """
    return keys.load_public_key(pem)


def load_private_key_pem(
    pem: str | bytes, password: bytes | None = None
) -> RSAPrivateKey:
    """Load an RSA private key from PKCS#8 PEM.

    Args:
        pem (str | bytes): PKCS#8 `PRIVATE KEY` PEM (optionally encrypted).
        password (bytes | None): Decryption password for an encrypted PEM.
            `None` for an unencrypted key.

    Raises:
        InvalidKeyError: If the PEM is PKCS#1, unparseable, or not RSA.

    Returns:
        RSAPrivateKey: The loaded private key.
    """
    return keys.load_private_key(pem, password=password)


def key_hash(key: RSAPublicKey | RSAPrivateKey) -> str:
    """Return the 64-char lowercase hex SHA-256 of the SPKI DER.

    Args:
        key (RSAPublicKey | RSAPrivateKey): Public or private RSA key. A
            private key is routed through its public half.

    Returns:
        str: The key hash (spec section 9.2).
    """
    return keys.key_hash(key)


def encrypt(
    plaintext: str,
    *,
    recipient_public_key: RSAPublicKey,
    sender_private_key: RSAPrivateKey,
    suite: Suite = Suite.RSA_OAEP_AES256GCM_SHA256,
    message_id: str | None = None,
    timestamp_ms: int | None = None,
) -> str:
    """Produce a wire message per the spec section 10.1 procedure.

    Args:
        plaintext (str): The user's message. NFC-normalized before encoding.
        recipient_public_key (RSAPublicKey): Recipient encryption key.
        sender_private_key (RSAPrivateKey): Sender signing key.
        suite (Suite): Cryptographic suite. Defaults to the hybrid suite
            (`RSA-OAEP-AES256GCM-SHA256`), which has no plaintext cap.
        message_id (str | None): Override for the body `i` field. When
            `None`, a fresh UUIDv4 is generated. Intended for deterministic
            tests; production callers leave it `None`.
        timestamp_ms (int | None): Override for the body `t` field. When
            `None`, the current Unix time in milliseconds is used.

    Raises:
        InvalidKeyError: If either key fails the section 8.2 modulus checks.
        PlaintextTooLargeError: If the plaintext exceeds the direct suite's
            `modulus - 66` cap, or the assembled hybrid body exceeds the
            section 6.5 size limit.

    Returns:
        str: A `PLAINCLOAK:v1:BR:<base62>` wire string.
    """
    suite_impl = get_suite(suite.value)

    keys.check_rsa_modulus(sender_private_key)
    keys.check_rsa_modulus(recipient_public_key)

    normalized = unicodedata.normalize("NFC", plaintext)
    message_bytes = normalized.encode("utf-8")

    cap = suite_impl.max_plaintext_bytes(recipient_public_key)
    if cap is not None and len(message_bytes) > cap:
        raise PlaintextTooLargeError(
            f"plaintext is {len(message_bytes)} bytes; suite {suite.value} "
            f"caps at {cap} bytes for this recipient key"
        )

    a = suite.value
    i = message_id if message_id is not None else str(uuid.uuid4())
    t = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
    s = keys.key_hash(sender_private_key)
    r = keys.key_hash(recipient_public_key)

    def _aad() -> bytes:
        return canonical.build_aad(
            wire_version_int=WIRE_VERSION_INT, a=a, i=i, t=t, s=s, r=r
        )

    payload = suite_impl.encrypt_payload(
        message_bytes,
        recipient_public_key=recipient_public_key,
        aad_factory=_aad,
    )
    p = base64.b64encode(payload).decode("ascii")

    canonical_bytes = canonical.build_canonical(
        wire_version_int=WIRE_VERSION_INT, a=a, i=i, t=t, s=s, r=r, p=p
    )
    signature = suite_base.sign(canonical_bytes, sender_private_key)
    g = base64.b64encode(signature).decode("ascii")

    message_body = {"a": a, "i": i, "t": t, "s": s, "r": r, "p": p, "g": g}
    body.validate(message_body)

    serialized = body.serialize(message_body)
    if cap is None and len(serialized) > _BODY_SIZE_LIMIT:
        raise PlaintextTooLargeError(
            f"assembled body is {len(serialized)} bytes; exceeds the "
            f"{_BODY_SIZE_LIMIT}-byte practical limit (spec section 6.5)"
        )

    compressed = compression.compress(serialized, code="BR")
    return format_envelope(comp_code="BR", payload_bytes=compressed)


def _index_private_keys(
    own_private_keys: Sequence[RSAPrivateKey] | Mapping[str, RSAPrivateKey],
) -> dict[str, RSAPrivateKey]:
    """Build a key-hash -> private-key index.

    Args:
        own_private_keys: Either a sequence of private keys (the hash is
            computed for each) or a mapping already keyed by key hash.

    Returns:
        dict[str, RSAPrivateKey]: Lookup keyed by SPKI hex digest.
    """
    if isinstance(own_private_keys, Mapping):
        return dict(own_private_keys)
    return {keys.key_hash(pk): pk for pk in own_private_keys}


def decrypt(
    wire: str,
    *,
    own_private_keys: Sequence[RSAPrivateKey] | Mapping[str, RSAPrivateKey],
    trusted_senders: Mapping[str, RSAPublicKey] | None = None,
    decompress_budget_bytes: int = DEFAULT_DECOMPRESS_BUDGET,
) -> DecryptResult:
    """Consume a wire message per the spec section 10.2 procedure.

    Structural failures (bad envelope, decompression, JSON, schema, unknown
    suite) raise a `MalformedWireError` subclass. The five section 10.3
    outcomes are returned in the `DecryptResult`, never raised.

    Args:
        wire (str): Candidate wire string (already trimmed of channel noise).
        own_private_keys: The consumer's private keys, as a sequence or a
            mapping keyed by key hash.
        trusted_senders (Mapping[str, RSAPublicKey] | None): Trusted sender
            public keys keyed by key hash. Empty/`None` means every message
            resolves to `unknown-sender`.
        decompress_budget_bytes (int): Streaming decompression cap. Defaults
            to 1 MiB.

    Raises:
        MalformedWireError: For any structural failure of spec section 3.3
            steps (envelope, decompression, JSON, schema, unknown suite).
        InvalidKeyError: If the private key matched by the body's `r` field
            or the trusted-sender key matched by its `s` field fails the
            section 8.2 modulus-size or public-exponent checks. Unmatched
            keys are not validated here; the PEM loaders are the entry gate.

    Returns:
        DecryptResult: Outcome plus metadata; plaintext is present only for
            `verified`, `signature-invalid`, and `unknown-sender`.
    """
    senders: Mapping[str, RSAPublicKey] = trusted_senders or {}
    private_index = _index_private_keys(own_private_keys)

    parsed = _parse_wire(wire)
    decompressed = compression.decompress(
        parsed.payload_bytes,
        code=parsed.comp_code,
        budget_bytes=decompress_budget_bytes,
    )
    message_body = body.parse(decompressed)
    body.validate(message_body)

    a = message_body["a"]
    i = message_body["i"]
    t = message_body["t"]
    s = message_body["s"]
    r = message_body["r"]
    p = message_body["p"]
    g = message_body["g"]

    suite_impl = get_suite(a)

    def _result(outcome: Outcome, plaintext: str | None) -> DecryptResult:
        return DecryptResult(
            outcome=outcome,
            plaintext=plaintext,
            suite=a,
            message_id=i,
            timestamp_ms=t,
            sender_key_hash=s,
            recipient_key_hash=r,
        )

    recipient_private_key = private_index.get(r)
    if recipient_private_key is None:
        return _result(Outcome.WRONG_RECIPIENT, None)
    keys.check_rsa_modulus(recipient_private_key)

    def _aad() -> bytes:
        return canonical.build_aad(
            wire_version_int=parsed.wire_version_int,
            a=a,
            i=i,
            t=t,
            s=s,
            r=r,
        )

    try:
        payload = base64.b64decode(p, validate=True)
        plaintext_bytes = suite_impl.decrypt_payload(
            payload,
            recipient_private_key=recipient_private_key,
            aad_factory=_aad,
        )
        plaintext = plaintext_bytes.decode("utf-8")
    except (suite_base._DecryptionFailed, UnicodeDecodeError, binascii.Error):
        return _result(Outcome.DECRYPTION_FAILED, None)

    canonical_bytes = canonical.build_canonical(
        wire_version_int=parsed.wire_version_int,
        a=a,
        i=i,
        t=t,
        s=s,
        r=r,
        p=p,
    )

    sender_public_key = senders.get(s)
    if sender_public_key is None:
        return _result(Outcome.UNKNOWN_SENDER, plaintext)
    keys.check_rsa_modulus(sender_public_key)

    try:
        signature = base64.b64decode(g, validate=True)
    except binascii.Error:
        return _result(Outcome.SIGNATURE_INVALID, plaintext)

    if suite_base.verify(canonical_bytes, signature, sender_public_key):
        return _result(Outcome.VERIFIED, plaintext)
    return _result(Outcome.SIGNATURE_INVALID, plaintext)


def encode_qr(wire: str, *, error_correction: str = "M") -> QRImage:
    """Render a wire string as a single QR-code image (optional `[qr]` extra).

    Args:
        wire (str): The wire string to encode.
        error_correction (str): EC level `L`/`M`/`Q`/`H`. Defaults to `M`.

    Raises:
        QRDependencyMissingError: If the `[qr]` extra is not installed.
        MessageTooLargeForQRError: If the wire overflows a single QR.

    Returns:
        QRImage: A Pillow image, ready to `.save(path)`.
    """
    return _qr.encode(wire, error_correction=error_correction)


def decode_qr(image_path: Path) -> str:
    """Decode a wire string from a saved QR image file (optional `[qr]` extra).

    Args:
        image_path (Path): Path to a saved QR image (PNG / JPG).

    Raises:
        QRDependencyMissingError: If the `[qr]` decode backend is absent.
        QRDecodeError: If no decodable QR matrix is found.

    Returns:
        str: The decoded wire string.
    """
    return _qr.decode(image_path)


def max_qr_wire_bytes(error_correction: str = "M") -> int:
    """Return the single-QR wire capacity for an EC level (no extra needed).

    Args:
        error_correction (str): EC level `L`/`M`/`Q`/`H`. Defaults to `M`.

    Returns:
        int: Maximum wire length in bytes for a single version-40 QR.
    """
    return _qr.max_wire_bytes(error_correction)


def parse_envelope(wire: str) -> EnvelopeInfo:
    """Return wire metadata without performing any decryption.

    Runs the spec section 3.3 structural pipeline and body validation, then
    surfaces metadata only. No private key is required or used.

    Args:
        wire (str): Candidate wire string.

    Raises:
        MalformedWireError: For any structural failure (envelope,
            decompression, JSON, schema).

    Returns:
        EnvelopeInfo: Suite, message id, timestamp, key hashes, and the
            payload/signature/body byte lengths.
    """
    parsed = _parse_wire(wire)
    decompressed = compression.decompress(
        parsed.payload_bytes, code=parsed.comp_code
    )
    message_body = body.parse(decompressed)
    body.validate(message_body)

    try:
        payload_len = len(base64.b64decode(message_body["p"], validate=True))
        signature_len = len(base64.b64decode(message_body["g"], validate=True))
    except binascii.Error as exc:
        raise InvalidBodyError(
            f"body Base64 field could not be decoded: {exc}"
        ) from exc

    return EnvelopeInfo(
        suite=message_body["a"],
        message_id=message_body["i"],
        timestamp_ms=message_body["t"],
        sender_key_hash=message_body["s"],
        recipient_key_hash=message_body["r"],
        payload_len=payload_len,
        signature_len=signature_len,
        body_len=len(decompressed),
    )
