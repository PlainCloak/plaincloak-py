from __future__ import annotations

import hashlib

import pytest

from plaincloak.core import keys
from plaincloak.exceptions import InvalidKeyError
from tests.conftest import KEYS_DIR, PEMKey


class TestKeyHashVector:
    """`key_hash` reproduces the locked digests from the 05 vector."""

    @pytest.mark.parametrize(
        ("stem", "bits", "expected"),
        [
            (
                "alice",
                2048,
                "1bf44bedd390cd114d5511c53286330f29c9fe70a4ab86118731860898ef88da",
            ),
            (
                "bob",
                4096,
                "b3cef20ec636c4125ae580da93dc0f13bdcdb1c3eea907543ed35ad52e024aee",
            ),
            (
                "stranger",
                2048,
                "a27738025c3f283be7d33c8502aabd4fb4daf06da1a033550e70f48aaa23b8bc",
            ),
        ],
    )
    def test_public_key_hash_matches_vector(
        self, stem: str, bits: int, expected: str
    ) -> None:
        pem = (KEYS_DIR / f"{stem}-rsa{bits}-pub.pem").read_bytes()
        assert keys.key_hash(keys.load_public_key(pem)) == expected

    def test_private_key_routes_through_public_half(self) -> None:
        pub = (KEYS_DIR / "alice-rsa2048-pub.pem").read_bytes()
        priv = (KEYS_DIR / "alice-rsa2048-priv.pem").read_bytes()
        assert keys.key_hash(keys.load_private_key(priv)) == keys.key_hash(
            keys.load_public_key(pub)
        )


class TestSpkiDer:
    """`spki_der` produces the exact bytes hashed by `key_hash`."""

    def test_spki_der_sha256_equals_key_hash(self, alice_pem: PEMKey) -> None:
        pub = keys.load_public_key(alice_pem.public_pem)
        digest = hashlib.sha256(keys.spki_der(pub)).hexdigest()
        assert digest == keys.key_hash(pub)


class TestPkcs1Rejection:
    """PKCS#1 PEM labels are rejected before the X.509 loader runs."""

    def test_pkcs1_public_label_rejected(self) -> None:
        pkcs1 = b"-----BEGIN RSA PUBLIC KEY-----\nMEg=\n-----END RSA PUBLIC KEY-----\n"
        with pytest.raises(InvalidKeyError, match="PKCS#1"):
            keys.load_public_key(pkcs1)

    def test_pkcs1_private_label_rejected(self) -> None:
        pkcs1 = (
            b"-----BEGIN RSA PRIVATE KEY-----\nMEg=\n"
            b"-----END RSA PRIVATE KEY-----\n"
        )
        with pytest.raises(InvalidKeyError, match="PKCS#1"):
            keys.load_private_key(pkcs1)

    def test_garbage_pem_rejected(self) -> None:
        with pytest.raises(InvalidKeyError):
            keys.load_public_key(b"not a pem at all")


class TestModulusChecks:
    """`check_rsa_modulus` and `modulus_bytes` per spec section 8.2."""

    def test_alice_2048_modulus_bytes(self, alice_pem: PEMKey) -> None:
        pub = keys.load_public_key(alice_pem.public_pem)
        assert keys.modulus_bytes(pub) == 256

    def test_bob_4096_modulus_bytes(self, bob_pem: PEMKey) -> None:
        pub = keys.load_public_key(bob_pem.public_pem)
        assert keys.modulus_bytes(pub) == 512

    def test_valid_keys_pass_modulus_check(
        self, alice_pem: PEMKey, bob_pem: PEMKey
    ) -> None:
        keys.check_rsa_modulus(keys.load_public_key(alice_pem.public_pem))
        keys.check_rsa_modulus(keys.load_private_key(bob_pem.private_pem))

    def test_generate_keypair_rejects_bad_size(self) -> None:
        with pytest.raises(InvalidKeyError):
            keys.generate_keypair(bits=1024)

    def test_generated_2048_key_is_valid(self) -> None:
        priv = keys.generate_keypair(bits=2048)
        keys.check_rsa_modulus(priv)
        assert keys.modulus_bytes(priv) == 256
