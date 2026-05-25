from __future__ import annotations


class PlainCloakError(Exception):
    """Base class for every error raised by the PlainCloak library."""


class MalformedWireError(PlainCloakError):
    """Wire string failed structural validation (spec section 3.6).

    Subclasses pinpoint which step of the parser rejected the input. Callers
    that only care that the wire is bad can catch this base class.
    """


class UnsupportedVersionError(MalformedWireError):
    """Wire format version token is not `v1`."""


class UnknownCompressionError(MalformedWireError):
    """Compression code is not registered for produce or consume in v1."""


class InvalidBase62Error(MalformedWireError):
    """Payload contains a character outside the Base62 alphabet."""


class DecompressionFailedError(MalformedWireError):
    """Brotli decompression raised an error on the payload bytes."""


class DecompressedTooLargeError(MalformedWireError):
    """Decompressed body exceeded the consumer's budget (default 1 MiB)."""


class InvalidJSONError(MalformedWireError):
    """Decompressed body was not valid UTF-8 JSON."""


class InvalidBodyError(MalformedWireError):
    """Body JSON did not validate against `message.schema.json`."""


class UnknownSuiteError(MalformedWireError):
    """Body declared a `suite` not present in this implementation's registry."""


class InvalidKeyError(PlainCloakError):
    """Producer-side: an RSA key fails modulus, exponent, or PEM-label checks."""


class PlaintextTooLargeError(PlainCloakError):
    """Producer-side: plaintext exceeds the suite's maximum length.

    For the direct suite (`RSA-OAEP-SHA256`) this is `modulus_bytes - 66`.
    For the hybrid suite it is the spec section 6.5 body cap.
    """


class KeystoreError(PlainCloakError):
    """Base class for keystore IO and crypto failures."""


class KeystoreLockedError(KeystoreError):
    """Keystore could not be unlocked.

    Raised opaquely for both wrong-password and structurally-corrupt files,
    so attackers cannot distinguish the two cases.
    """


class KeystoreFormatError(KeystoreError):
    """Keystore JSON did not validate against `keystore.schema.json`."""


class QRError(PlainCloakError):
    """Base class for the optional single-QR transport layer."""


class QRDependencyMissingError(QRError):
    """The `[qr]` extra is not installed, so QR encode/decode is unavailable."""


class MessageTooLargeForQRError(QRError):
    """Wire string exceeds the version-40 byte-mode capacity for the EC level."""


class QRDecodeError(QRError):
    """No decodable QR matrix was found in the supplied image."""
