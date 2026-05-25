from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).resolve().parent / "vectors" / "v1"
KEYS_DIR = VECTORS_DIR / "fixtures" / "keys"


@dataclass(frozen=True, slots=True)
class PEMKey:
    """A fixture keypair as raw PEM bytes (no `cryptography` import here).

    Keeping the fixture light avoids forcing M2/M3 modules to load just to
    run unit tests that do not need actual key objects.
    """

    name: str
    bits: int
    public_pem: bytes
    private_pem: bytes


def _load_pem(stem: str, bits: int) -> PEMKey:
    """Load one alice/bob/stranger PEM pair from the vendored fixtures."""
    pub = (KEYS_DIR / f"{stem}-rsa{bits}-pub.pem").read_bytes()
    priv = (KEYS_DIR / f"{stem}-rsa{bits}-priv.pem").read_bytes()
    return PEMKey(name=stem, bits=bits, public_pem=pub, private_pem=priv)


@pytest.fixture(scope="session")
def vectors_dir() -> Path:
    """Return the vendored `tests/vectors/v1/` root path."""
    return VECTORS_DIR


@pytest.fixture(scope="session")
def alice_pem() -> PEMKey:
    """Alice's 2048-bit RSA keypair (from the spec fixtures)."""
    return _load_pem("alice", 2048)


@pytest.fixture(scope="session")
def bob_pem() -> PEMKey:
    """Bob's 4096-bit RSA keypair (from the spec fixtures)."""
    return _load_pem("bob", 4096)


@pytest.fixture(scope="session")
def stranger_pem() -> PEMKey:
    """Stranger's 2048-bit RSA keypair (untrusted sender / unintended recipient)."""
    return _load_pem("stranger", 2048)
