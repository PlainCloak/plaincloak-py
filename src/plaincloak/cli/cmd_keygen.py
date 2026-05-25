from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from cryptography.hazmat.primitives import serialization

from plaincloak.cli import _io
from plaincloak.core import keys
from plaincloak.core.keystore import Keystore
from plaincloak.exceptions import PlainCloakError


def keygen_command(
    ctx: typer.Context,
    bits: Annotated[
        int, typer.Option("--bits", help="Modulus size: 2048/3072/4096.")
    ] = 4096,
    out_pub: Annotated[
        Path | None,
        typer.Option(
            "--out-pub", help="Write SPKI public PEM here (no keystore)."
        ),
    ] = None,
    out_priv: Annotated[
        Path | None,
        typer.Option(
            "--out-priv", help="Write PKCS#8 private PEM here (no keystore)."
        ),
    ] = None,
    label: Annotated[
        str | None,
        typer.Option(
            "--label", help="Store as a keystore entry under this label."
        ),
    ] = None,
    password_stdin: Annotated[
        bool,
        typer.Option(
            "--password-stdin", help="Read keystore passphrase from stdin."
        ),
    ] = False,
) -> None:
    """Generate a keypair. With `--label`, persist into the keystore;
    otherwise write SPKI + PKCS#8 PEM files."""
    state = ctx.obj
    try:
        if bits not in (2048, 3072, 4096):
            raise typer.BadParameter("bits must be 2048, 3072, or 4096")

        private_key = keys.generate_keypair(bits=bits)
        public_key = private_key.public_key()
        key_hash = keys.key_hash(public_key)

        if label is not None:
            path = state.keystore_path
            existing = path.exists()
            # Loading needs no passphrase; peek at whether any key exists so
            # we know if this is the keystore's first key.
            has_keys = bool(
                existing and Keystore.load(path).list_my_keys()
            )
            # Confirm (double-entry) only when setting a new passphrase, i.e.
            # the first key in this keystore. A typo there would otherwise
            # lock the keystore with an unknown passphrase.
            password = _io.read_password(
                password_stdin=password_stdin, confirm=not has_keys
            )
            if existing:
                store = Keystore.load(path, password)
                # Reject a wrong passphrase up front; otherwise add_my_key
                # would encrypt this key under a different passphrase than
                # the existing entries, silently splitting the keystore.
                store.verify_password()
            else:
                store = Keystore.init(path, password)
            store.add_my_key(label, private_key)
            store.save()
            if state.json_output:
                _io.emit_json(
                    {"label": label, "key_hash": key_hash, "keystore": str(path)}
                )
            else:
                _io.emit_success(
                    f"stored key {label!r}",
                    detail=f"{_io.short_hash(key_hash)} → {path}",
                )
            raise typer.Exit(0)

        if out_pub is None or out_priv is None:
            raise typer.BadParameter(
                "without --label, both --out-pub and --out-priv are required"
            )
        out_pub.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        out_priv.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        if state.json_output:
            _io.emit_json(
                {
                    "key_hash": key_hash,
                    "public_key": str(out_pub),
                    "private_key": str(out_priv),
                }
            )
        else:
            _io.emit_success(
                "generated keypair", detail=_io.short_hash(key_hash)
            )
        raise typer.Exit(0)
    except ValueError as exc:
        _io.emit_error(str(exc))
        raise typer.Exit(1) from exc
    except PlainCloakError as exc:
        _io.emit_error(str(exc))
        raise typer.Exit(_io.error_exit_code(exc)) from exc
