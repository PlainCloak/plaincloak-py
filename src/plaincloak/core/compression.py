from __future__ import annotations

import brotli

from plaincloak.core.constants import DEFAULT_DECOMPRESS_BUDGET
from plaincloak.exceptions import (
    DecompressedTooLargeError,
    DecompressionFailedError,
    UnknownCompressionError,
)

_BROTLI_QUALITY: int = 11
_BROTLI_LGWIN: int = 22
_CHUNK_SIZE: int = 16 * 1024

CODES_KNOWN_CONSUME: frozenset[str] = frozenset({"BR", "NO"})
CODES_KNOWN_PRODUCE: frozenset[str] = frozenset({"BR"})
CODES_RESERVED: frozenset[str] = frozenset({"ZS"})


def compress(data: bytes, *, code: str = "BR", _allow_no: bool = False) -> bytes:
    """Compress `data` with the given codec.

    Args:
        data (bytes): Input bytes.
        code (str): Compression code from the spec section 5.1 registry.
            Defaults to `"BR"`.
        _allow_no (bool): Internal flag to permit `"NO"` (identity).
            Default `False`. Production code paths MUST NOT set this.

    Raises:
        UnknownCompressionError: If `code` is not a registered produce code.

    Returns:
        bytes: Compressed bytes.
    """
    if code == "BR":
        compressed: bytes = brotli.compress(
            data,
            mode=brotli.MODE_GENERIC,
            quality=_BROTLI_QUALITY,
            lgwin=_BROTLI_LGWIN,
        )
        return compressed
    if code == "NO" and _allow_no:
        return data
    if code in CODES_RESERVED:
        raise UnknownCompressionError(
            f"compression code {code!r} is reserved and MUST NOT be produced"
        )
    raise UnknownCompressionError(
        f"compression code {code!r} is not registered for produce"
    )


def decompress(
    data: bytes,
    *,
    code: str,
    budget_bytes: int = DEFAULT_DECOMPRESS_BUDGET,
) -> bytes:
    """Decompress `data` with the given codec, enforcing a streaming budget.

    Args:
        data (bytes): Compressed input bytes.
        code (str): Compression code from the spec section 5.1 registry.
        budget_bytes (int): Maximum allowed decompressed size. Default 1 MiB
            (`DEFAULT_DECOMPRESS_BUDGET`). The check fires inside the loop, so
            a bomb aborts as soon as the cumulative output crosses the budget.

    Raises:
        UnknownCompressionError: If `code` is not in `CODES_KNOWN_CONSUME`.
        DecompressionFailedError: If the underlying decoder rejects `data`.
        DecompressedTooLargeError: If output exceeds `budget_bytes`.

    Returns:
        bytes: Decompressed bytes.
    """
    if code == "BR":
        return _decompress_brotli(data, budget_bytes=budget_bytes)
    if code == "NO":
        if len(data) > budget_bytes:
            raise DecompressedTooLargeError(
                f"identity payload ({len(data)} bytes) exceeds "
                f"decompression budget ({budget_bytes} bytes)"
            )
        return data
    if code in CODES_RESERVED:
        raise UnknownCompressionError(
            f"compression code {code!r} is reserved in v1"
        )
    raise UnknownCompressionError(
        f"compression code {code!r} is not registered for consume"
    )


def _decompress_brotli(data: bytes, *, budget_bytes: int) -> bytes:
    """Streaming Brotli decompression with per-chunk budget enforcement.

    Args:
        data (bytes): Brotli compressed input.
        budget_bytes (int): Maximum cumulative decompressed size.

    Raises:
        DecompressionFailedError: If `data` is not a valid Brotli stream or
            ends mid-stream.
        DecompressedTooLargeError: If accumulated output crosses `budget_bytes`.

    Returns:
        bytes: Decompressed output.
    """
    decoder = brotli.Decompressor()
    out = bytearray()
    view = memoryview(data)
    offset = 0
    try:
        while offset < len(view):
            chunk = bytes(view[offset : offset + _CHUNK_SIZE])
            offset += _CHUNK_SIZE
            piece = decoder.process(chunk)
            if piece:
                if len(out) + len(piece) > budget_bytes:
                    raise DecompressedTooLargeError(
                        f"decompressed output exceeded budget "
                        f"({budget_bytes} bytes)"
                    )
                out.extend(piece)
        if not decoder.is_finished():
            raise DecompressionFailedError(
                "brotli stream ended before final block"
            )
    except brotli.error as exc:
        raise DecompressionFailedError(f"brotli decode failed: {exc}") from exc
    return bytes(out)
