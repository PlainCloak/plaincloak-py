from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from plaincloak import api
from plaincloak.core import base62, body, canonical, compression, keys
from plaincloak.exceptions import InvalidBase62Error, InvalidBodyError

_VECTORS_ROOT = Path(__file__).resolve().parent.parent / "vectors" / "v1"


CaseInputs = dict[str, Any]
CaseExpected = dict[str, Any]
Handler = Callable[[CaseInputs, CaseExpected], None]


def _run_base62_encode(inputs: CaseInputs, expected: CaseExpected) -> None:
    """Compare encoder output against the locked Base62 string."""
    data = bytes.fromhex(inputs["bytes_hex"])
    assert base62.encode(data) == expected["base62"]


def _run_base62_decode(inputs: CaseInputs, expected: CaseExpected) -> None:
    """Decode and compare to the locked hex, or assert rejection.

    Reject cases carry `reject: True` and an `error` of `invalid-base62`
    instead of a `bytes_hex`; the decoder must raise `InvalidBase62Error`.
    """
    if expected.get("reject"):
        with pytest.raises(InvalidBase62Error):
            base62.decode(inputs["base62"])
        return
    out = base62.decode(inputs["base62"])
    assert out.hex() == expected["bytes_hex"]


def _run_brotli_roundtrip(inputs: CaseInputs, expected: CaseExpected) -> None:
    """Round-trip property: decompress(compress(input)) == input."""
    data = bytes.fromhex(inputs["input_hex"])
    compressed = compression.compress(data, code="BR")
    assert compression.decompress(compressed, code="BR") == data
    assert data.hex() == expected["decompressed_hex"]


def _run_canonical_form(inputs: CaseInputs, expected: CaseExpected) -> None:
    """Build canonical form from the locked body and compare bytes."""
    b = inputs["body"]
    out = canonical.build_canonical(
        wire_version_int=inputs["wire_version_int"],
        a=b["a"],
        i=b["i"],
        t=b["t"],
        s=b["s"],
        r=b["r"],
        p=b["p"],
    )
    assert out == expected["canonical"].encode("utf-8")


def _run_msg_id_formatting(inputs: CaseInputs, expected: CaseExpected) -> None:
    """Use the message-body schema as the oracle for `i` acceptance."""
    candidate = {
        "a": "RSA-OAEP-SHA256",
        "i": inputs["candidate"],
        "t": 0,
        "s": "0" * 64,
        "r": "f" * 64,
        "p": "QUJDRA==",
        "g": "QUJDRA==",
    }
    if expected["accept"]:
        body.validate(candidate)
    else:
        with pytest.raises(InvalidBodyError):
            body.validate(candidate)


def _resolve_key_path(spec_path: str) -> Path:
    """Map a spec-rooted fixture path to the vendored vectors tree.

    Vector files reference keys as `test-vectors/v1/fixtures/keys/<name>`;
    the vendored snapshot lives under `tests/vectors/v1/fixtures/keys/`.
    """
    marker = "test-vectors/v1/"
    tail = spec_path.split(marker, 1)[1] if marker in spec_path else spec_path
    return _VECTORS_ROOT / tail


def _run_key_hash_spki(inputs: CaseInputs, expected: CaseExpected) -> None:
    """Hash the referenced SPKI PEM and compare to the locked digest."""
    pem = _resolve_key_path(inputs["public_key_pem_path"]).read_bytes()
    public_key = keys.load_public_key(pem)
    assert keys.key_hash(public_key) == expected["key_hash"]


def _run_verification(inputs: CaseInputs, expected: CaseExpected) -> None:
    """Drive `api.decrypt` and assert the outcome, plaintext, and metadata.

    Covers every verification category (roundtrip, tampered-*, wrong-
    recipient, unknown-sender, hybrid-*). They share one handler because the
    consumer procedure (spec section 10.2) is identical; only the fixtures
    and expected outcome differ.
    """
    recipient_priv = keys.load_private_key(
        _resolve_key_path(inputs["recipient_priv_pem_path"]).read_bytes()
    )
    trusted_senders = {
        entry["key_hash"]: keys.load_public_key(
            _resolve_key_path(entry["public_key_pem_path"]).read_bytes()
        )
        for entry in inputs.get("trusted_senders", [])
    }

    result = api.decrypt(
        inputs["wire"],
        own_private_keys=[recipient_priv],
        trusted_senders=trusted_senders,
    )

    assert result.outcome.value == expected["outcome"]

    if expected.get("plaintext_present") is False:
        assert result.plaintext is None
    if "plaintext" in expected:
        assert result.plaintext == expected["plaintext"]
    if "msg_id" in expected:
        assert result.message_id == expected["msg_id"]
    if "timestamp" in expected:
        assert result.timestamp_ms == expected["timestamp"]
    if "sender_key_hash" in expected:
        assert result.sender_key_hash == expected["sender_key_hash"]
    if "recipient_key_hash" in expected:
        assert result.recipient_key_hash == expected["recipient_key_hash"]


_VERIFICATION_CATEGORIES = (
    "rsa2048-roundtrip",
    "rsa4096-roundtrip",
    "tampered-payload",
    "tampered-signature",
    "wrong-recipient",
    "unknown-sender",
    "rsa2048-hybrid-roundtrip",
    "rsa4096-hybrid-roundtrip",
    "hybrid-long-plaintext",
    "hybrid-tampered-wrap",
    "hybrid-tampered-tag",
    "hybrid-signature-invalid",
)

HANDLERS: dict[str, Handler] = {
    "base62-encode": _run_base62_encode,
    "base62-decode": _run_base62_decode,
    "brotli-roundtrip": _run_brotli_roundtrip,
    "canonical-form": _run_canonical_form,
    "msg-id-formatting": _run_msg_id_formatting,
    "key-hash-spki": _run_key_hash_spki,
    **{cat: _run_verification for cat in _VERIFICATION_CATEGORIES},
}


def dispatch(category: str, inputs: CaseInputs, expected: CaseExpected) -> None:
    """Run the handler for `category`.

    Args:
        category (str): Vector file's `category` field.
        inputs (CaseInputs): The case's `inputs` dict.
        expected (CaseExpected): The case's `expected` dict.

    Raises:
        pytest.skip.Exception: If no handler is registered for `category` yet.
            Subsequent milestones add handlers; the skip keeps the parametrized
            test surface stable.
    """
    handler = HANDLERS.get(category)
    if handler is None:
        pytest.skip(f"no handler registered for category {category!r} yet")
        return
    handler(inputs, expected)
