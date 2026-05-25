from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from plaincloak.api import encrypt
from plaincloak.cli import _io
from plaincloak.core.keystore import Keystore
from plaincloak.exceptions import PlainCloakError
from plaincloak.types import Suite

_SUITES = {
    "hybrid": Suite.RSA_OAEP_AES256GCM_SHA256,
    "direct": Suite.RSA_OAEP_SHA256,
}


def encrypt_command(
    ctx: typer.Context,
    to: Annotated[
        str | None,
        typer.Option(
            "--to", help="Recipient key hash or contact alias (keystore)."
        ),
    ] = None,
    to_pubkey: Annotated[
        Path | None,
        typer.Option(
            "--to-pubkey", help="Recipient SPKI PEM file (skip keystore)."
        ),
    ] = None,
    from_label: Annotated[
        str | None, typer.Option("--from", help="Sender keystore label.")
    ] = None,
    from_privkey: Annotated[
        Path | None,
        typer.Option(
            "--from-privkey", help="Sender PKCS#8 PEM file (skip keystore)."
        ),
    ] = None,
    suite: Annotated[
        str,
        typer.Option("--suite", help="Cryptographic suite: hybrid or direct."),
    ] = "hybrid",
    message: Annotated[
        str | None, typer.Option("--message", help="Plaintext literal.")
    ] = None,
    in_path: Annotated[
        str | None,
        typer.Option("--in", help="Read plaintext from file, or - for stdin."),
    ] = None,
    out_path: Annotated[
        str | None,
        typer.Option("--out", help="Write wire to file (default stdout)."),
    ] = None,
    password_stdin: Annotated[
        bool,
        typer.Option(
            "--password-stdin", help="Read keystore passphrase from stdin."
        ),
    ] = False,
) -> None:
    """Encrypt and sign a message into a `PLAINCLOAK:v1:BR:...` string."""
    state = ctx.obj
    try:
        if suite not in _SUITES:
            raise typer.BadParameter("suite must be 'hybrid' or 'direct'")

        store: Keystore | None = None
        need_keystore = to is not None or from_label is not None
        if need_keystore:
            password = _io.read_password(password_stdin=password_stdin)
            store = Keystore.load(state.keystore_path, password)

        recipient_public_key = _resolve_recipient(to, to_pubkey, store)
        sender_private_key = _resolve_sender(from_label, from_privkey, store)

        plaintext_bytes = _io.read_input(message, in_path)
        wire = encrypt(
            plaintext_bytes.decode("utf-8"),
            recipient_public_key=recipient_public_key,
            sender_private_key=sender_private_key,
            suite=_SUITES[suite],
        )
        _io.write_output(wire.encode("utf-8"), out_path)
        if out_path not in (None, "-"):
            _io.emit_stderr(f"wrote wire to {out_path}")
        raise typer.Exit(0)
    except (PlainCloakError, ValueError) as exc:
        _io.emit_error(str(exc))
        code = (
            _io.error_exit_code(exc)
            if isinstance(exc, PlainCloakError)
            else 1
        )
        raise typer.Exit(code) from exc


def _resolve_recipient(
    to: str | None, to_pubkey: Path | None, store: Keystore | None
) -> RSAPublicKey:
    """Resolve the recipient public key from a file or the keystore."""
    from plaincloak.core import keys

    if to_pubkey is not None:
        return keys.load_public_key(to_pubkey.read_bytes())
    if to is None or store is None:
        raise typer.BadParameter("provide --to (keystore) or --to-pubkey")
    entry = store.lookup_by_alias_or_hash(to)
    if entry is None:
        raise typer.BadParameter(f"no contact or key matching {to!r}")
    return entry.public_key


def _resolve_sender(
    from_label: str | None,
    from_privkey: Path | None,
    store: Keystore | None,
) -> RSAPrivateKey:
    """Resolve the sender private key from a file or the keystore."""
    from plaincloak.core import keys

    if from_privkey is not None:
        return keys.load_private_key(from_privkey.read_bytes())
    if from_label is None or store is None:
        raise typer.BadParameter("provide --from (keystore) or --from-privkey")
    return store.decrypt_private_key(from_label)
