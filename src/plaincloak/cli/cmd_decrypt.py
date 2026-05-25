from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from plaincloak.api import decrypt
from plaincloak.cli import _io
from plaincloak.core import keys
from plaincloak.core.keystore import Keystore
from plaincloak.exceptions import PlainCloakError


def decrypt_command(
    ctx: typer.Context,
    wire: Annotated[
        str | None,
        typer.Argument(help="Wire string, or omit and use --in / -."),
    ] = None,
    in_path: Annotated[
        str | None,
        typer.Option("--in", help="Read wire from file, or - for stdin."),
    ] = None,
    from_privkey: Annotated[
        Path | None,
        typer.Option("--from-privkey", help="Private PEM (skip keystore)."),
    ] = None,
    out_path: Annotated[
        str | None,
        typer.Option(
            "--out", help="Write plaintext to file (default stdout)."
        ),
    ] = None,
    password_stdin: Annotated[
        bool,
        typer.Option(
            "--password-stdin", help="Read keystore passphrase from stdin."
        ),
    ] = False,
) -> None:
    """Decrypt a wire message and report the outcome."""
    state = ctx.obj
    try:
        wire_text = _resolve_wire(wire, in_path, password_stdin)

        sender_names: dict[str, str] = {}
        recipient_names: dict[str, str] = {}

        if from_privkey is not None:
            own_keys = [keys.load_private_key(from_privkey.read_bytes())]
            trusted: dict[str, RSAPublicKey] = {}
        else:
            password = (
                _PASSWORD_HOLDER.pop()
                if _PASSWORD_HOLDER
                else _io.read_password(password_stdin=password_stdin)
            )
            store = Keystore.load(state.keystore_path, password)
            own_keys = [
                store.decrypt_private_key(entry.key_hash)
                for entry in store.list_my_keys()
            ]
            trusted = {
                c.key_hash: c.public_key
                for c in store.list_contacts()
            }
            sender_names = {
                c.key_hash: c.alias for c in store.list_contacts()
            }
            recipient_names = {
                e.key_hash: e.label for e in store.list_my_keys()
            }

        result = decrypt(
            wire_text,
            own_private_keys=own_keys,
            trusted_senders=trusted,
        )

        if state.json_output:
            # The plaintext is already inside the JSON; only also write it
            # out when an explicit file target was given, so stdout is not a
            # duplicate of plaintext followed by the JSON object.
            if result.plaintext is not None and out_path not in (None, "-"):
                _io.write_output(result.plaintext.encode("utf-8"), out_path)
            _io.emit_json(
                {
                    "outcome": result.outcome.value,
                    "plaintext": result.plaintext,
                    "suite": result.suite,
                    "message_id": result.message_id,
                    "timestamp_ms": result.timestamp_ms,
                    "sender_key_hash": result.sender_key_hash,
                    "recipient_key_hash": result.recipient_key_hash,
                }
            )
        else:
            if result.plaintext is not None:
                _io.emit_plaintext(result.plaintext, out_path)
            _io.emit_decrypt_report(
                outcome=result.outcome,
                suite=result.suite,
                sender_key_hash=result.sender_key_hash,
                recipient_key_hash=result.recipient_key_hash,
                message_id=result.message_id,
                timestamp_ms=result.timestamp_ms,
                had_plaintext=result.plaintext is not None,
                sender_name=sender_names.get(result.sender_key_hash),
                recipient_name=recipient_names.get(
                    result.recipient_key_hash
                ),
            )

        raise typer.Exit(_io.outcome_exit_code(result.outcome))
    except PlainCloakError as exc:
        _io.emit_error(str(exc))
        raise typer.Exit(_io.error_exit_code(exc)) from exc


# When wire and password both arrive on stdin, the password is split off
# first and stashed here so the keystore branch does not re-read stdin.
_PASSWORD_HOLDER: list[bytes] = []


def _resolve_wire(
    wire: str | None, in_path: str | None, password_stdin: bool
) -> str:
    """Resolve the wire string, handling shared stdin with the password.

    Args:
        wire (str | None): Positional wire argument, if given.
        in_path (str | None): `--in` path or `-` for stdin.
        password_stdin (bool): Whether the passphrase also comes from stdin.

    Raises:
        ValueError: If no wire source was provided.

    Returns:
        str: The wire string, stripped of trailing whitespace/newline.
    """
    if wire is not None and wire != "-":
        return wire.strip()
    if wire != "-" and in_path is None:
        raise ValueError("no wire provided (expected an argument, --in, or -)")
    if in_path is not None and in_path != "-":
        from pathlib import Path

        return Path(in_path).read_text(encoding="utf-8").strip()

    raw = sys.stdin.buffer.read().decode("utf-8")
    if password_stdin:
        first, _, rest = raw.partition("\n")
        _PASSWORD_HOLDER.append(first.rstrip("\r").encode("utf-8"))
        return rest.strip()
    return raw.strip()
