from __future__ import annotations

import base64
import json
import os
import time
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from plaincloak.core import keys
from plaincloak.exceptions import (
    KeystoreError,
    KeystoreFormatError,
    KeystoreLockedError,
)
from plaincloak.types import ContactEntry, OwnKeyEntry

_KEYSTORE_VERSION: int = 1
_SALT_LEN: int = 16
_NONCE_LEN: int = 12
_AEAD_KEY_LEN: int = 32

# OWASP 2023 guidance.
_PBKDF2_ITERATIONS: int = 600_000
_ARGON2_PARAMS: dict[str, int] = {"m_kib": 19456, "t": 2, "p": 1}

_DEFAULT_AEAD: str = "aes-256-gcm"


def _to_own_key_entry(entry: dict[str, Any]) -> OwnKeyEntry:
    """Convert a raw `my_keys` dict to a typed `OwnKeyEntry`."""
    return OwnKeyEntry(
        label=entry["label"],
        key_hash=entry["key_hash"],
        public_key=keys.load_public_key(entry["public_key_pem"]),
        created_at=entry["created_at"],
        expires_at=entry.get("expires_at"),
    )


def _to_contact_entry(entry: dict[str, Any]) -> ContactEntry:
    """Convert a raw `contacts` dict to a typed `ContactEntry`."""
    return ContactEntry(
        alias=entry["alias"],
        key_hash=entry["key_hash"],
        public_key=keys.load_public_key(entry["public_key_pem"]),
        added_at=entry["added_at"],
        verified_at=entry.get("verified_at"),
        notes=entry.get("notes", ""),
    )


def _argon2_available() -> bool:
    """Return True if the optional `argon2-cffi` dependency is importable."""
    try:
        import argon2  # noqa: F401
    except ImportError:
        return False
    return True


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    """Return a cached validator for the keystore schema."""
    schema_text = (
        files("plaincloak.core.schemas")
        .joinpath("keystore.schema.json")
        .read_text(encoding="utf-8")
    )
    schema = json.loads(schema_text)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _b64e(raw: bytes) -> str:
    """Base64-encode bytes to an ASCII string."""
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    """Base64-decode an ASCII string to bytes."""
    return base64.b64decode(text)


def _derive_key(
    password: bytes, salt: bytes, kdf_name: str, params: dict[str, Any]
) -> bytes:
    """Derive a 32-byte AEAD key from the password.

    Args:
        password (bytes): The user's passphrase.
        salt (bytes): KDF salt.
        kdf_name (str): `argon2id` or `pbkdf2-sha256`.
        params (dict[str, Any]): KDF parameters from the keystore header.

    Raises:
        KeystoreError: If `kdf_name` is `argon2id` but `argon2-cffi` is not
            installed, or if `kdf_name` is unknown.

    Returns:
        bytes: 32-byte derived key.
    """
    if kdf_name == "pbkdf2-sha256":
        import hashlib

        return hashlib.pbkdf2_hmac(
            "sha256",
            password,
            salt,
            int(params["iterations"]),
            dklen=_AEAD_KEY_LEN,
        )
    if kdf_name == "argon2id":
        if not _argon2_available():
            raise KeystoreError(
                "keystore uses argon2id but the optional 'argon2-cffi' "
                "dependency is not installed; install plaincloak[keystore]"
            )
        from argon2.low_level import Type, hash_secret_raw

        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=int(params["t"]),
            memory_cost=int(params["m_kib"]),
            parallelism=int(params["p"]),
            hash_len=_AEAD_KEY_LEN,
            type=Type.ID,
        )
    raise KeystoreError(f"unknown KDF {kdf_name!r}")


def _aead_encrypt(
    aead_name: str, key: bytes, nonce: bytes, plaintext: bytes
) -> bytes:
    """AEAD-encrypt with the named cipher (tag appended to ciphertext)."""
    if aead_name == "aes-256-gcm":
        return AESGCM(key).encrypt(nonce, plaintext, None)
    if aead_name == "chacha20-poly1305":
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    raise KeystoreError(f"unknown AEAD {aead_name!r}")


def _aead_decrypt(
    aead_name: str, key: bytes, nonce: bytes, ciphertext: bytes
) -> bytes:
    """AEAD-decrypt with the named cipher.

    Raises:
        KeystoreLockedError: If the tag check fails (wrong password or
            corrupt ciphertext - the two are not distinguished).
        KeystoreError: If `aead_name` is unknown.
    """
    try:
        if aead_name == "aes-256-gcm":
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        if aead_name == "chacha20-poly1305":
            return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise KeystoreLockedError(
            "keystore could not be unlocked"
        ) from exc
    raise KeystoreError(f"unknown AEAD {aead_name!r}")


class Keystore:
    """A passphrase-locked store of own keypairs and trusted contacts.

    Hold the instance only as long as needed; it keeps the passphrase in
    memory to encrypt new keys and decrypt existing ones.
    """

    def __init__(
        self, path: Path, password: bytes | None, data: dict[str, Any]
    ):
        """Construct from already-validated data. Use `init`/`load` instead.

        Args:
            path (Path): Filesystem path backing this keystore.
            password (bytes | None): The user's passphrase, or `None` when
                the keystore was opened for public-data-only operations
                (listing keys/contacts, exporting a public key, adding a
                contact). Private-key operations raise if it is `None`.
            data (dict[str, Any]): Schema-valid keystore document.
        """
        self._path = path
        self._password = password
        self._data = data

    def _require_password(self) -> bytes:
        """Return the passphrase or raise if the keystore was opened without one.

        Raises:
            KeystoreError: If no passphrase is held (opened for read-only
                public access).

        Returns:
            bytes: The held passphrase.
        """
        if self._password is None:
            raise KeystoreError(
                "this operation needs a passphrase; reopen the keystore "
                "with one"
            )
        return self._password

    # ---- construction -------------------------------------------------

    @classmethod
    def init(
        cls,
        path: Path,
        password: bytes,
        *,
        aead_name: str = _DEFAULT_AEAD,
    ) -> Keystore:
        """Create a new empty keystore and write it atomically.

        Argon2id is selected when `argon2-cffi` is importable; otherwise the
        keystore falls back to PBKDF2-SHA256 so a base install still works.

        Args:
            path (Path): Destination path. Must not already exist.
            password (bytes): Passphrase that will lock private keys.
            aead_name (str): `aes-256-gcm` (default) or `chacha20-poly1305`.

        Raises:
            KeystoreError: If `path` already exists.

        Returns:
            Keystore: The new, empty keystore.
        """
        if path.exists():
            raise KeystoreError(f"keystore already exists at {path}")
        if _argon2_available():
            kdf = {"name": "argon2id", "params": dict(_ARGON2_PARAMS)}
        else:
            kdf = {
                "name": "pbkdf2-sha256",
                "params": {"iterations": _PBKDF2_ITERATIONS},
            }
        data: dict[str, Any] = {
            "version": _KEYSTORE_VERSION,
            "kdf": kdf,
            "aead": {"name": aead_name},
            "my_keys": [],
            "contacts": [],
        }
        store = cls(path, password, data)
        store.save()
        return store

    @classmethod
    def load(cls, path: Path, password: bytes | None = None) -> Keystore:
        """Load and schema-validate a keystore from disk.

        The password is not verified at load time; a wrong password is
        detected only when a private key is decrypted (`decrypt_private_key`
        or `verify_password`) because the schema defines no password
        verifier. Pass `password=None` for public-data-only operations
        (listing, exporting a public key, adding a contact).

        Args:
            path (Path): Keystore file path.
            password (bytes | None): Passphrase for later private-key
                operations, or `None` for public-data-only access.

        Raises:
            KeystoreError: If the file does not exist.
            KeystoreFormatError: If the file is not valid JSON or fails
                schema validation.

        Returns:
            Keystore: The loaded keystore.
        """
        if not path.exists():
            raise KeystoreError(f"no keystore at {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise KeystoreFormatError(
                f"keystore is not valid JSON: {exc}"
            ) from exc
        try:
            _validator().validate(data)
        except ValidationError as exc:
            path_str = ".".join(str(p) for p in exc.absolute_path) or "<root>"
            raise KeystoreFormatError(
                f"keystore failed schema validation at {path_str}: "
                f"{exc.message}"
            ) from exc
        return cls(path, password, data)

    # ---- persistence --------------------------------------------------

    def save(self) -> None:
        """Validate and write the keystore atomically (tmp then replace).

        Raises:
            KeystoreFormatError: If the in-memory document is not schema
                valid (guards against constructing a corrupt file).
        """
        try:
            _validator().validate(self._data)
        except ValidationError as exc:
            raise KeystoreFormatError(
                f"refusing to write schema-invalid keystore: {exc.message}"
            ) from exc
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        os.replace(tmp, self._path)

    # ---- mutation -----------------------------------------------------

    def add_my_key(
        self,
        label: str,
        private_key: RSAPrivateKey,
        *,
        expires_at: int | None = None,
    ) -> OwnKeyEntry:
        """Encrypt and store an own private key under `label`.

        Args:
            label (str): Human-readable label (e.g. `"Personal"`).
            private_key (RSAPrivateKey): The keypair to store.
            expires_at (int | None): Optional key-rotation deadline (Unix ms).

        Raises:
            KeystoreError: If an own key with `label` already exists.

        Returns:
            OwnKeyEntry: The stored entry with metadata and public key.
        """
        if any(k["label"] == label for k in self._data["my_keys"]):
            raise KeystoreError(f"own key with label {label!r} already exists")
        public_key = private_key.public_key()
        pkcs8_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        password = self._require_password()
        salt = os.urandom(_SALT_LEN)
        nonce = os.urandom(_NONCE_LEN)
        kdf = self._data["kdf"]
        derived = _derive_key(password, salt, kdf["name"], kdf["params"])
        ciphertext = _aead_encrypt(
            self._data["aead"]["name"], derived, nonce, pkcs8_pem
        )
        spki_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        entry: dict[str, Any] = {
            "label": label,
            "key_hash": keys.key_hash(public_key),
            "public_key_pem": spki_pem,
            "private_key_enc": {
                "salt": _b64e(salt),
                "nonce": _b64e(nonce),
                "ciphertext": _b64e(ciphertext),
            },
            "created_at": int(time.time() * 1000),
        }
        if expires_at is not None:
            entry["expires_at"] = expires_at
        self._data["my_keys"].append(entry)
        return _to_own_key_entry(entry)

    def add_contact(
        self,
        alias: str,
        public_key_pem: str | bytes,
        *,
        notes: str = "",
        verified_at: int | None = None,
    ) -> ContactEntry:
        """Add a trusted contact public key.

        Args:
            alias (str): Human-readable contact name.
            public_key_pem (str | bytes): Contact's SPKI PEM. Validated by
                loading it; PKCS#1 is rejected.
            notes (str): Optional free-text notes.
            verified_at (int | None): Time the key was confirmed out of band.

        Raises:
            InvalidKeyError: If the PEM is not a valid SPKI RSA key.
            KeystoreError: If a contact with `alias` already exists.

        Returns:
            ContactEntry: The stored entry with metadata and public key.
        """
        if any(c["alias"] == alias for c in self._data["contacts"]):
            raise KeystoreError(f"contact with alias {alias!r} already exists")
        public_key = keys.load_public_key(public_key_pem)
        spki_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        entry: dict[str, Any] = {
            "alias": alias,
            "key_hash": keys.key_hash(public_key),
            "public_key_pem": spki_pem,
            "added_at": int(time.time() * 1000),
        }
        if verified_at is not None:
            entry["verified_at"] = verified_at
        if notes:
            entry["notes"] = notes
        self._data["contacts"].append(entry)
        return _to_contact_entry(entry)

    def set_contact_verified(
        self,
        alias_or_hash: str,
        *,
        verified: bool,
        when_ms: int | None = None,
    ) -> ContactEntry:
        """Mark a contact verified out of band, or clear that mark.

        Verification records that you confirmed the contact's public key
        through a trusted channel (in person, signed message, etc.); it does
        not change decrypt outcomes, it is a trust reminder.

        Args:
            alias_or_hash (str): Contact alias or key hash.
            verified (bool): True to stamp `verified_at`, False to clear it.
            when_ms (int | None): Verification time in Unix ms. Defaults to
                now when `verified` is True. Ignored when clearing.

        Raises:
            KeystoreError: If no contact matches.

        Returns:
            ContactEntry: The updated entry.
        """
        contact = self._find_contact(alias_or_hash)
        if contact is None:
            raise KeystoreError(f"no contact matching {alias_or_hash!r}")
        if verified:
            contact["verified_at"] = (
                when_ms if when_ms is not None else int(time.time() * 1000)
            )
        else:
            contact.pop("verified_at", None)
        return _to_contact_entry(contact)

    def rename_contact(
        self, alias_or_hash: str, new_alias: str
    ) -> ContactEntry:
        """Change a contact's alias.

        Args:
            alias_or_hash (str): Current alias or key hash.
            new_alias (str): The new alias.

        Raises:
            KeystoreError: If no contact matches, or another contact already
                uses `new_alias`.

        Returns:
            ContactEntry: The updated entry.
        """
        contact = self._find_contact(alias_or_hash)
        if contact is None:
            raise KeystoreError(f"no contact matching {alias_or_hash!r}")
        if any(
            c["alias"] == new_alias and c is not contact
            for c in self._data["contacts"]
        ):
            raise KeystoreError(
                f"contact with alias {new_alias!r} already exists"
            )
        contact["alias"] = new_alias
        return _to_contact_entry(contact)

    def set_contact_notes(
        self, alias_or_hash: str, notes: str
    ) -> ContactEntry:
        """Replace a contact's free-text notes.

        Args:
            alias_or_hash (str): Contact alias or key hash.
            notes (str): New notes. An empty string removes the field.

        Raises:
            KeystoreError: If no contact matches.

        Returns:
            ContactEntry: The updated entry.
        """
        contact = self._find_contact(alias_or_hash)
        if contact is None:
            raise KeystoreError(f"no contact matching {alias_or_hash!r}")
        if notes:
            contact["notes"] = notes
        else:
            contact.pop("notes", None)
        return _to_contact_entry(contact)

    def remove_contact(self, alias_or_hash: str) -> ContactEntry:
        """Delete a contact.

        Args:
            alias_or_hash (str): Contact alias or key hash.

        Raises:
            KeystoreError: If no contact matches.

        Returns:
            ContactEntry: The removed entry.
        """
        contact = self._find_contact(alias_or_hash)
        if contact is None:
            raise KeystoreError(f"no contact matching {alias_or_hash!r}")
        self._data["contacts"].remove(contact)
        return _to_contact_entry(contact)

    def rename_my_key(
        self, label_or_hash: str, new_label: str
    ) -> OwnKeyEntry:
        """Change an own key's label.

        Args:
            label_or_hash (str): Current label or key hash.
            new_label (str): The new label.

        Raises:
            KeystoreError: If no own key matches, or another own key already
                uses `new_label`.

        Returns:
            OwnKeyEntry: The updated entry.
        """
        entry = self._find_my_key(label_or_hash)
        if entry is None:
            raise KeystoreError(
                f"no own key with label or hash {label_or_hash!r}"
            )
        if any(
            e["label"] == new_label and e is not entry
            for e in self._data["my_keys"]
        ):
            raise KeystoreError(f"own key with label {new_label!r} already exists")
        entry["label"] = new_label
        return _to_own_key_entry(entry)

    def set_my_key_expiry(
        self, label_or_hash: str, expires_at_ms: int | None
    ) -> OwnKeyEntry:
        """Set or clear an own key's rotation deadline.

        This is a rotation reminder, not message expiry; nothing enforces it
        at encrypt or decrypt time.

        Args:
            label_or_hash (str): Own key label or key hash.
            expires_at_ms (int | None): Deadline in Unix ms, or None to clear.

        Raises:
            KeystoreError: If no own key matches.

        Returns:
            OwnKeyEntry: The updated entry.
        """
        entry = self._find_my_key(label_or_hash)
        if entry is None:
            raise KeystoreError(
                f"no own key with label or hash {label_or_hash!r}"
            )
        if expires_at_ms is None:
            entry.pop("expires_at", None)
        else:
            entry["expires_at"] = expires_at_ms
        return _to_own_key_entry(entry)

    def remove_my_key(self, label_or_hash: str) -> OwnKeyEntry:
        """Delete an own key, including its encrypted private key.

        This is irreversible: messages encrypted to this key can no longer be
        decrypted unless the private key was backed up elsewhere.

        Args:
            label_or_hash (str): Own key label or key hash.

        Raises:
            KeystoreError: If no own key matches.

        Returns:
            OwnKeyEntry: The removed entry (metadata only).
        """
        entry = self._find_my_key(label_or_hash)
        if entry is None:
            raise KeystoreError(
                f"no own key with label or hash {label_or_hash!r}"
            )
        self._data["my_keys"].remove(entry)
        return _to_own_key_entry(entry)

    # ---- access -------------------------------------------------------

    def decrypt_private_key(self, label_or_hash: str) -> RSAPrivateKey:
        """Decrypt and return an own private key.

        Args:
            label_or_hash (str): An own key's `label` or `key_hash`.

        Raises:
            KeystoreError: If no own key matches `label_or_hash`.
            KeystoreLockedError: If the password is wrong or the stored
                ciphertext is corrupt (the two are not distinguished).

        Returns:
            RSAPrivateKey: The decrypted private key.
        """
        entry = self._find_my_key(label_or_hash)
        if entry is None:
            raise KeystoreError(
                f"no own key with label or hash {label_or_hash!r}"
            )
        password = self._require_password()
        enc = entry["private_key_enc"]
        salt = _b64d(enc["salt"])
        nonce = _b64d(enc["nonce"])
        ciphertext = _b64d(enc["ciphertext"])
        kdf = self._data["kdf"]
        derived = _derive_key(password, salt, kdf["name"], kdf["params"])
        pkcs8_pem = _aead_decrypt(
            self._data["aead"]["name"], derived, nonce, ciphertext
        )
        return keys.load_private_key(pkcs8_pem)

    def verify_password(self) -> None:
        """Check the held passphrase against an existing private key.

        Trial-decrypts the first `my_keys` entry. This catches a wrong
        passphrase early - in particular before `add_my_key` would otherwise
        write a new key under a different passphrase than the existing
        entries, silently corrupting the keystore.

        No-op when the keystore has no own keys yet (nothing to verify
        against) or when opened without a passphrase.

        Raises:
            KeystoreLockedError: If the passphrase does not match the
                existing keys (raised opaquely by `decrypt_private_key`).
        """
        if self._password is None or not self._data["my_keys"]:
            return
        self.decrypt_private_key(self._data["my_keys"][0]["key_hash"])

    def export_pubkey(self, label_or_hash: str) -> str:
        """Return the SPKI PEM of an own key or a contact.

        Args:
            label_or_hash (str): Own key label/hash or contact alias/hash.

        Raises:
            KeystoreError: If nothing matches.

        Returns:
            str: SPKI PEM string.
        """
        entry = self.lookup_by_alias_or_hash(label_or_hash)
        if entry is None:
            raise KeystoreError(
                f"no key or contact matching {label_or_hash!r}"
            )
        return entry.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def list_my_keys(self) -> list[OwnKeyEntry]:
        """Return own-key entries (metadata only; private keys stay encrypted)."""
        return [_to_own_key_entry(e) for e in self._data["my_keys"]]

    def list_contacts(self) -> list[ContactEntry]:
        """Return the contact entries."""
        return [_to_contact_entry(c) for c in self._data["contacts"]]

    def lookup_by_alias_or_hash(
        self, query: str
    ) -> OwnKeyEntry | ContactEntry | None:
        """Find an own key (by label/hash) or contact (by alias/hash).

        Args:
            query (str): Label, alias, or 64-hex key hash.

        Returns:
            OwnKeyEntry | ContactEntry | None: The first matching entry, or None.
        """
        own = self._find_my_key(query)
        if own is not None:
            return _to_own_key_entry(own)
        for contact in self._data["contacts"]:
            if query in (contact["alias"], contact["key_hash"]):
                return _to_contact_entry(contact)
        return None

    def _find_my_key(self, label_or_hash: str) -> dict[str, Any] | None:
        """Return the own-key entry matching a label or key hash, or None."""
        for entry in self._data["my_keys"]:
            if label_or_hash in (entry["label"], entry["key_hash"]):
                return cast(dict[str, Any], entry)
        return None

    def _find_contact(self, alias_or_hash: str) -> dict[str, Any] | None:
        """Return the contact entry matching an alias or key hash, or None."""
        for contact in self._data["contacts"]:
            if alias_or_hash in (contact["alias"], contact["key_hash"]):
                return cast(dict[str, Any], contact)
        return None
