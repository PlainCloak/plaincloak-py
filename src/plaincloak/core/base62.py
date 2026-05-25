from __future__ import annotations

from plaincloak.core.constants import BASE62_ALPHABET, BASE62_INDEX
from plaincloak.exceptions import InvalidBase62Error


def encode(data: bytes) -> str:
    """Encode an octet string to Base62 per spec section 4.2.

    Args:
        data (bytes): Octet string to encode. May be empty.

    Returns:
        str: Base62 string drawn from `BASE62_ALPHABET`. Empty input maps to
            the empty string; a `0x00` prefix of length `Z` maps to `Z`
            leading `0` characters.
    """
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break

    n = int.from_bytes(data, "big") if data else 0

    if n == 0:
        return BASE62_ALPHABET[0] * leading_zeros

    digits: list[str] = []
    while n > 0:
        n, r = divmod(n, 62)
        digits.append(BASE62_ALPHABET[r])
    digits.reverse()
    return BASE62_ALPHABET[0] * leading_zeros + "".join(digits)


def decode(text: str) -> bytes:
    """Decode a Base62 string to its octet string per spec section 4.3.

    Args:
        text (str): Base62 string to decode. Every character MUST be in the
            alphabet of section 4.1; otherwise the decoder rejects.

    Raises:
        InvalidBase62Error: If `text` contains any character not in
            `BASE62_ALPHABET`.

    Returns:
        bytes: Decoded octet string. The empty input maps to `b""`; a
            sequence of leading `0` characters reproduces a `0x00` prefix
            of the same length.
    """
    if not text:
        return b""

    leading_zeros = 0
    for ch in text:
        if ch == BASE62_ALPHABET[0]:
            leading_zeros += 1
        else:
            break

    tail = text[leading_zeros:]
    n = 0
    for ch in tail:
        v = BASE62_INDEX.get(ch)
        if v is None:
            raise InvalidBase62Error(
                f"character {ch!r} is not in the Base62 alphabet"
            )
        n = n * 62 + v

    if n == 0:
        return b"\x00" * leading_zeros

    body_len = (n.bit_length() + 7) // 8
    return b"\x00" * leading_zeros + n.to_bytes(body_len, "big")
