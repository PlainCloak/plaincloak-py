from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

from plaincloak.exceptions import (
    MessageTooLargeForQRError,
    QRDecodeError,
    QRDependencyMissingError,
)

if TYPE_CHECKING:
    from PIL.Image import Image

# Version-40 byte-mode data capacity (bytes) for each error-correction level,
# from the QR Code spec (ISO/IEC 18004 Table 7). The wire string is lowercase
# base62, so QR alphanumeric mode is unavailable and byte mode applies.
_BYTE_CAPACITY_V40: dict[str, int] = {
    "L": 2953,
    "M": 2331,
    "Q": 1663,
    "H": 1273,
}


def max_wire_bytes(error_correction: str = "M") -> int:
    """Return the largest wire string that fits in a single QR at this EC level.

    Pure capacity math against the version-40 byte-mode table; needs none of
    the optional `[qr]` dependencies.

    Args:
        error_correction (str): Error-correction level, one of `L`, `M`, `Q`,
            `H` (case-insensitive). Defaults to `M`.

    Raises:
        ValueError: If `error_correction` is not a known level.

    Returns:
        int: Maximum wire length in bytes for a single version-40 QR.
    """
    level = error_correction.upper()
    if level not in _BYTE_CAPACITY_V40:
        raise ValueError(
            f"error_correction MUST be one of L, M, Q, H; got "
            f"{error_correction!r}"
        )
    return _BYTE_CAPACITY_V40[level]


def encode(wire: str, *, error_correction: str = "M") -> Image:
    """Render a wire string as a single QR-code image.

    The wire string is treated as opaque ASCII; this function never parses or
    validates it. Pins to the smallest QR version that fits (`fit=True`) for a
    minimal module count.

    Args:
        wire (str): The `PLAINCLOAK:v1:...` wire string to encode.
        error_correction (str): Error-correction level, one of `L`, `M`, `Q`,
            `H` (case-insensitive). Defaults to `M`.

    Raises:
        QRDependencyMissingError: If the `[qr]` extra is not installed.
        MessageTooLargeForQRError: If the wire exceeds the single-QR capacity
            for the chosen EC level.
        ValueError: If `error_correction` is not a known level.

    Returns:
        Image: A Pillow image of the QR code, ready to `.save(path)`.
    """
    cap = max_wire_bytes(error_correction)
    size = len(wire.encode("ascii"))
    if size > cap:
        raise MessageTooLargeForQRError(
            f"wire is {size} bytes; a single QR at EC level "
            f"{error_correction.upper()} holds at most {cap} bytes. Split the "
            f"message or use a smaller key."
        )

    try:
        import qrcode
        from qrcode.constants import (
            ERROR_CORRECT_H,
            ERROR_CORRECT_L,
            ERROR_CORRECT_M,
            ERROR_CORRECT_Q,
        )
    except ImportError as exc:
        raise QRDependencyMissingError(
            "QR encoding needs the optional `[qr]` extra "
            "(pip install plaincloak[qr])"
        ) from exc

    levels = {
        "L": ERROR_CORRECT_L,
        "M": ERROR_CORRECT_M,
        "Q": ERROR_CORRECT_Q,
        "H": ERROR_CORRECT_H,
    }
    qr = qrcode.QRCode(error_correction=levels[error_correction.upper()])
    qr.add_data(wire)
    qr.make(fit=True)
    return cast("Image", qr.make_image().get_image())


def decode(image_path: Path) -> str:
    """Decode a wire string from a saved QR-code image file.

    Reads a PNG or JPG with Pillow (image IO only) and runs the zbar matrix
    decoder on it. Never touches a live camera or scanner. The returned string
    is verbatim apart from stripping surrounding whitespace; validation happens
    downstream in `decrypt` / `parse_envelope`.

    zbar is used rather than OpenCV's `QRCodeDetector` because a PlainCloak
    wire fills a dense version-26/27 byte-mode QR, which OpenCV decodes only
    intermittently; zbar reads those reliably.

    Args:
        image_path (Path): Path to a saved QR image (PNG / JPG).

    Raises:
        QRDependencyMissingError: If the `[qr]` decode backend is not installed.
        QRDecodeError: If no decodable QR matrix is found in the image.

    Returns:
        str: The decoded wire string.
    """
    try:
        from PIL import Image as PILImage
        from pyzbar.pyzbar import ZBarSymbol
        from pyzbar.pyzbar import decode as zbar_decode
    except ImportError as exc:
        raise QRDependencyMissingError(
            "QR decoding needs the optional `[qr]` extra "
            "(pip install plaincloak[qr])"
        ) from exc

    with PILImage.open(image_path) as img:
        # Decode in grayscale; restricting to QR symbols skips zbar's other
        # one-dimensional decoders (and their spurious warnings).
        results = zbar_decode(img.convert("L"), symbols=[ZBarSymbol.QRCODE])

    if not results:
        raise QRDecodeError(f"no QR code found in {image_path}")
    return cast(str, results[0].data.decode("utf-8")).strip()
