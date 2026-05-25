from __future__ import annotations

MAGIC: str = "PLAINCLOAK"
VERSION_TOKEN: str = "v1"
WIRE_VERSION_INT: int = 1

DEFAULT_DECOMPRESS_BUDGET: int = 1_048_576  # 1 MiB, spec section 5.4

BASE62_ALPHABET: str = (
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)

BASE62_INDEX: dict[str, int] = {ch: i for i, ch in enumerate(BASE62_ALPHABET)}
