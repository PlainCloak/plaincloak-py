from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from plaincloak.core import keys
from plaincloak.core.keystore import Keystore, _argon2_available
from plaincloak.exceptions import (
    KeystoreError,
    KeystoreFormatError,
    KeystoreLockedError,
)

_PW = b"correct horse battery staple"
_WRONG = b"Tr0ub4dor&3"


@pytest.fixture
def alice_priv():
    return keys.generate_keypair(bits=2048)


@pytest.fixture
def bob_pub():
    return keys.generate_keypair(bits=2048).public_key()


class TestRoundTrip:
    """Init -> add -> save -> reopen -> decrypt returns the original key."""

    def test_full_roundtrip(
        self, tmp_path: Path, alice_priv, bob_pub
    ) -> None:
        path = tmp_path / "keystore.json"
        store = Keystore.init(path, _PW)
        store.add_my_key("Personal", alice_priv)
        bob_pem = bob_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        store.add_contact("Bob", bob_pem, notes="work key")
        store.save()

        reopened = Keystore.load(path, _PW)
        recovered = reopened.decrypt_private_key("Personal")
        assert keys.key_hash(recovered) == keys.key_hash(alice_priv)

    def test_lookup_by_hash_and_alias(
        self, tmp_path: Path, alice_priv, bob_pub
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        store.add_my_key("Work", alice_priv)
        store.add_contact(
            "Bob",
            bob_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        own_hash = keys.key_hash(alice_priv)
        assert store.lookup_by_alias_or_hash("Work").key_hash == own_hash
        assert store.lookup_by_alias_or_hash(own_hash).label == "Work"
        assert store.lookup_by_alias_or_hash("Bob").alias == "Bob"
        assert store.lookup_by_alias_or_hash("missing") is None

    def test_export_pubkey_roundtrips(
        self, tmp_path: Path, alice_priv
    ) -> None:
        store = Keystore.init(tmp_path / "k.json", _PW)
        store.add_my_key("Personal", alice_priv)
        pem = store.export_pubkey("Personal")
        loaded = keys.load_public_key(pem)
        assert keys.key_hash(loaded) == keys.key_hash(alice_priv)


class TestWrongPassword:
    """Wrong password is opaque: KeystoreLockedError, no sub-cause."""

    def test_wrong_password_raises_locked(
        self, tmp_path: Path, alice_priv
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        store.add_my_key("Personal", alice_priv)
        store.save()

        reopened = Keystore.load(path, _WRONG)
        with pytest.raises(KeystoreLockedError):
            reopened.decrypt_private_key("Personal")

    def test_verify_password_rejects_wrong_pw(
        self, tmp_path: Path, alice_priv
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        store.add_my_key("Personal", alice_priv)
        store.save()

        with pytest.raises(KeystoreLockedError):
            Keystore.load(path, _WRONG).verify_password()

    def test_verify_password_accepts_correct_pw(
        self, tmp_path: Path, alice_priv
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        store.add_my_key("Personal", alice_priv)
        store.save()
        Keystore.load(path, _PW).verify_password()  # no raise

    def test_verify_password_noop_when_empty_or_locked(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "ks.json"
        Keystore.init(path, _PW).save()
        Keystore.load(path, _PW).verify_password()  # no keys: no-op
        Keystore.load(path).verify_password()  # no password: no-op


class TestPublicOnlyAccess:
    """Read-only ops work without a passphrase; key ops require one."""

    def test_load_without_password_reads_public_data(
        self, tmp_path: Path, alice_priv, bob_pub
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        store.add_my_key("Personal", alice_priv)
        store.add_contact(
            "Bob",
            bob_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        store.save()

        public = Keystore.load(path)  # no password
        assert public.list_my_keys()[0].label == "Personal"
        assert public.list_contacts()[0].alias == "Bob"
        assert public.export_pubkey("Personal")

    def test_decrypt_without_password_raises(
        self, tmp_path: Path, alice_priv
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        store.add_my_key("Personal", alice_priv)
        store.save()

        with pytest.raises(KeystoreError):
            Keystore.load(path).decrypt_private_key("Personal")

    def test_add_my_key_without_password_raises(
        self, tmp_path: Path, alice_priv
    ) -> None:
        path = tmp_path / "ks.json"
        Keystore.init(path, _PW).save()
        with pytest.raises(KeystoreError):
            Keystore.load(path).add_my_key("Personal", alice_priv)

    def test_add_my_key_duplicate_label_raises(
        self, tmp_path: Path, alice_priv
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        store.add_my_key("Personal", alice_priv)
        with pytest.raises(KeystoreError, match="already exists"):
            store.add_my_key("Personal", alice_priv)

    def test_add_contact_duplicate_alias_raises(
        self, tmp_path: Path, alice_priv, bob_pub
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        bob_pem = bob_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        store.add_contact("Bob", bob_pem)
        with pytest.raises(KeystoreError, match="already exists"):
            store.add_contact("Bob", bob_pem)


class TestSchemaRejection:
    """Malformed files are rejected as KeystoreFormatError."""

    def test_not_json_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("this is not json", encoding="utf-8")
        with pytest.raises(KeystoreFormatError):
            Keystore.load(path, _PW)

    def test_schema_violation_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        # Missing required top-level fields.
        path.write_text(json.dumps({"version": 1}), encoding="utf-8")
        with pytest.raises(KeystoreFormatError):
            Keystore.load(path, _PW)

    def test_wrong_version_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text(
            json.dumps(
                {"version": 2, "my_keys": [], "contacts": []}
            ),
            encoding="utf-8",
        )
        with pytest.raises(KeystoreFormatError):
            Keystore.load(path, _PW)

    def test_missing_file_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(KeystoreError):
            Keystore.load(tmp_path / "nope.json", _PW)

    def test_init_refuses_existing_path(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "ks.json"
        Keystore.init(path, _PW)
        with pytest.raises(KeystoreError):
            Keystore.init(path, _PW)


class TestKdfDispatch:
    """KDF selection works with and without argon2-cffi."""

    def test_init_selects_argon2id_when_available(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "ks.json"
        Keystore.init(path, _PW)
        data = json.loads(path.read_text(encoding="utf-8"))
        expected = "argon2id" if _argon2_available() else "pbkdf2-sha256"
        assert data["kdf"]["name"] == expected

    @pytest.mark.skipif(
        not _argon2_available(), reason="argon2-cffi not installed"
    )
    def test_argon2_roundtrip(self, tmp_path: Path, alice_priv) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        assert store._data["kdf"]["name"] == "argon2id"
        store.add_my_key("Personal", alice_priv)
        store.save()
        reopened = Keystore.load(path, _PW)
        recovered = reopened.decrypt_private_key("Personal")
        assert keys.key_hash(recovered) == keys.key_hash(alice_priv)

    def test_pbkdf2_roundtrip(self, tmp_path: Path, alice_priv) -> None:
        # Force PBKDF2 regardless of argon2 availability.
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        store._data["kdf"] = {
            "name": "pbkdf2-sha256",
            "params": {"iterations": 200_000},
        }
        store.add_my_key("Personal", alice_priv)
        store.save()
        reopened = Keystore.load(path, _PW)
        recovered = reopened.decrypt_private_key("Personal")
        assert keys.key_hash(recovered) == keys.key_hash(alice_priv)

    def test_chacha20_aead_roundtrip(
        self, tmp_path: Path, alice_priv
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW, aead_name="chacha20-poly1305")
        store.add_my_key("Personal", alice_priv)
        store.save()
        reopened = Keystore.load(path, _PW)
        recovered = reopened.decrypt_private_key("Personal")
        assert keys.key_hash(recovered) == keys.key_hash(alice_priv)


class TestAtomicSave:
    """Save writes via a temp file and leaves no .tmp behind."""

    def test_no_tmp_left_after_save(
        self, tmp_path: Path, alice_priv
    ) -> None:
        path = tmp_path / "ks.json"
        store = Keystore.init(path, _PW)
        store.add_my_key("Personal", alice_priv)
        store.save()
        assert path.exists()
        assert not (tmp_path / "ks.json.tmp").exists()
