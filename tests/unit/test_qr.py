from __future__ import annotations

import sys

import pytest

from plaincloak.core import qr
from plaincloak.exceptions import (
    MessageTooLargeForQRError,
    QRDependencyMissingError,
)

try:
    import pyzbar.pyzbar  # noqa: F401
    import qrcode  # noqa: F401

    _QR_INSTALLED = True
except ImportError:
    _QR_INSTALLED = False

requires_qr = pytest.mark.skipif(
    not _QR_INSTALLED, reason="the [qr] extra is not installed"
)


class TestCapacity:
    """Version-40 byte-mode capacity per EC level is pure and dep-free."""

    @pytest.mark.parametrize(
        ("level", "expected"),
        [("L", 2953), ("M", 2331), ("Q", 1663), ("H", 1273)],
    )
    def test_known_levels(self, level: str, expected: int) -> None:
        assert qr.max_wire_bytes(level) == expected

    def test_default_is_m(self) -> None:
        assert qr.max_wire_bytes() == qr.max_wire_bytes("M")

    def test_level_is_case_insensitive(self) -> None:
        assert qr.max_wire_bytes("l") == qr.max_wire_bytes("L")

    def test_unknown_level_raises(self) -> None:
        with pytest.raises(ValueError, match="L, M, Q, H"):
            qr.max_wire_bytes("Z")


class TestEncodeGuards:
    """Encode rejects oversized wires before touching the optional backend."""

    def test_oversized_wire_raises(self) -> None:
        oversized = "x" * (qr.max_wire_bytes("M") + 1)
        with pytest.raises(MessageTooLargeForQRError):
            qr.encode(oversized)

    def test_largest_level_allows_more(self) -> None:
        # A wire that overflows H still fits L, so the EC level is honored.
        wire = "x" * (qr.max_wire_bytes("H") + 1)
        with pytest.raises(MessageTooLargeForQRError):
            qr.encode(wire, error_correction="H")


class TestDependencyGating:
    """A missing backend surfaces as QRDependencyMissingError, not ImportError."""

    def test_encode_without_qrcode(self, monkeypatch) -> None:
        monkeypatch.setitem(sys.modules, "qrcode", None)
        with pytest.raises(QRDependencyMissingError):
            qr.encode("PLAINCLOAK:v1:BR:abc")

    def test_decode_without_pyzbar(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setitem(sys.modules, "pyzbar.pyzbar", None)
        with pytest.raises(QRDependencyMissingError):
            qr.decode(tmp_path / "missing.png")


@requires_qr
class TestRoundTrip:
    """A real wire string survives encode -> save -> decode unchanged."""

    def _wire(self) -> str:
        from plaincloak import encrypt, generate_keypair

        recipient = generate_keypair(bits=2048)
        sender = generate_keypair(bits=2048)
        return encrypt(
            "qr round-trip ✓",
            recipient_public_key=recipient.public_key,
            sender_private_key=sender.private_key,
        )

    def test_encode_decode_roundtrip(self, tmp_path) -> None:
        wire = self._wire()
        path = tmp_path / "msg.png"
        qr.encode(wire).save(path)
        assert qr.decode(path) == wire

    def test_decode_no_qr_raises(self, tmp_path) -> None:
        from PIL import Image

        from plaincloak.exceptions import QRDecodeError

        blank = tmp_path / "blank.png"
        Image.new("RGB", (64, 64), "white").save(blank)
        with pytest.raises(QRDecodeError):
            qr.decode(blank)
