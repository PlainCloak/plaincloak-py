from __future__ import annotations

from dataclasses import dataclass

from plaincloak.core import base62
from plaincloak.core.compression import (
    CODES_KNOWN_CONSUME,
    CODES_KNOWN_PRODUCE,
    CODES_RESERVED,
)
from plaincloak.core.constants import (
    BASE62_INDEX,
    MAGIC,
    VERSION_TOKEN,
    WIRE_VERSION_INT,
)
from plaincloak.exceptions import (
    InvalidBase62Error,
    MalformedWireError,
    UnknownCompressionError,
    UnsupportedVersionError,
)


@dataclass(frozen=True, slots=True)
class ParsedEnvelope:
    """Result of `parse_envelope`: header fields and decoded payload bytes.

    Attributes:
        wire_version_int (int): Integer derived from the version token,
            e.g. `1` for `v1`. Used by the signature canonical form.
        version_token (str): Raw token from the envelope (e.g. `"v1"`).
        comp_code (str): Two-letter compression code from the section 5
            registry, e.g. `"BR"`.
        payload_bytes (bytes): Base62-decoded wire payload. These bytes are
            the input to the decompression layer.
    """

    wire_version_int: int
    version_token: str
    comp_code: str
    payload_bytes: bytes


def parse_envelope(wire: str) -> ParsedEnvelope:
    """Parse and validate a wire envelope per spec section 3.3.

    Args:
        wire (str): Candidate wire string. Trailing whitespace is ignored
            per spec section 3.3 step 5 (whitespace terminates the payload).
            Anything else outside the four spec-defined fields, including
            leading whitespace, is rejected.

    The fields are checked in the spec section 3.3 step order (magic, then
    version, then compression, then payload), so the error category reflects
    the first failing step: a `v2` envelope with a garbled payload reports
    `unsupported-version`, not `malformed`.

    Raises:
        MalformedWireError: Missing colon separators, magic mismatch, or an
            empty payload; a payload character outside the Base62 alphabet
            (including extra colons, per section 3.5) is raised as
            `InvalidBase62Error`.
        UnsupportedVersionError: Version token is not `v1`.
        UnknownCompressionError: Compression code is unknown or reserved.

    Returns:
        ParsedEnvelope: Decoded envelope ready for the decompression step.
    """
    if not isinstance(wire, str):
        raise MalformedWireError("wire input MUST be a string")
    wire = wire.rstrip()
    if not wire:
        raise MalformedWireError("wire input is empty")

    magic, sep, rest = wire.partition(":")
    if not sep:
        raise MalformedWireError("wire envelope has no colon separators")
    if magic != MAGIC:
        raise MalformedWireError(
            f"magic MUST be {MAGIC!r} (case-sensitive); got {magic!r}"
        )

    version, sep, rest = rest.partition(":")
    if not sep:
        raise MalformedWireError(
            "wire envelope is missing the compression and payload fields"
        )
    if version != VERSION_TOKEN:
        raise UnsupportedVersionError(
            f"version token MUST be {VERSION_TOKEN!r}; got {version!r}"
        )

    comp_code, sep, payload = rest.partition(":")
    if not sep:
        raise MalformedWireError("wire envelope is missing the payload field")
    if comp_code in CODES_RESERVED:
        raise UnknownCompressionError(
            f"compression code {comp_code!r} is reserved in v1"
        )
    if comp_code not in CODES_KNOWN_CONSUME:
        raise UnknownCompressionError(
            f"compression code {comp_code!r} is not in this consumer's registry"
        )

    if not payload:
        raise MalformedWireError("wire payload MUST NOT be empty")
    for ch in payload:
        if ch not in BASE62_INDEX:
            raise InvalidBase62Error(
                f"wire payload contains non-Base62 character {ch!r}"
            )

    payload_bytes = base62.decode(payload)

    return ParsedEnvelope(
        wire_version_int=WIRE_VERSION_INT,
        version_token=version,
        comp_code=comp_code,
        payload_bytes=payload_bytes,
    )


def format_envelope(*, comp_code: str, payload_bytes: bytes) -> str:
    """Build a wire string from a compression code and post-compression bytes.

    Args:
        comp_code (str): Two-letter compression code. MUST be registered for
            produce (e.g. `"BR"`).
        payload_bytes (bytes): Compressed body bytes. MUST be non-empty;
            a producer never emits an empty payload because the JSON body
            is never empty.

    Raises:
        UnknownCompressionError: If `comp_code` is not in the produce-side
            registry.
        MalformedWireError: If `payload_bytes` is empty.

    Returns:
        str: Wire string `PLAINCLOAK:v1:<comp_code>:<base62(payload)>`.
    """
    if not payload_bytes:
        raise MalformedWireError(
            "cannot format wire envelope with an empty payload"
        )
    if comp_code not in CODES_KNOWN_PRODUCE:
        raise UnknownCompressionError(
            f"compression code {comp_code!r} is not registered for produce"
        )
    return f"{MAGIC}:{VERSION_TOKEN}:{comp_code}:{base62.encode(payload_bytes)}"
