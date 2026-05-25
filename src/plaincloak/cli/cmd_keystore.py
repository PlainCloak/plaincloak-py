from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from plaincloak.cli import _io
from plaincloak.core import keys
from plaincloak.core.keystore import Keystore
from plaincloak.exceptions import PlainCloakError

keystore_app = typer.Typer(
    name="keystore",
    help="Create and manage the encrypted keystore.",
    no_args_is_help=True,
)


def _fail(exc: PlainCloakError) -> None:
    """Emit an error line and exit with the mapped code."""
    _io.emit_error(str(exc))
    raise typer.Exit(_io.error_exit_code(exc)) from exc


def _parse_expiry_to_ms(value: str) -> int:
    """Parse a date or ISO 8601 datetime into a Unix-ms timestamp.

    Accepts a bare date (`2027-01-01`, taken as UTC midnight) or a full
    datetime (`2027-01-01T09:30:00Z` or with a `+hh:mm` offset; naive values
    are assumed UTC).

    Args:
        value (str): The date or datetime string.

    Raises:
        typer.BadParameter: If the value cannot be parsed.

    Returns:
        int: The instant in Unix milliseconds.
    """
    from datetime import date, datetime, timezone

    raw = value.strip()
    try:
        if "T" not in raw and " " not in raw:
            day = date.fromisoformat(raw)
            dt = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise typer.BadParameter(
            f"could not parse {value!r} as a date or ISO 8601 datetime"
        ) from exc
    return int(dt.timestamp() * 1000)


@keystore_app.command("init")
def init_cmd(
    ctx: typer.Context,
    password_stdin: Annotated[
        bool,
        typer.Option("--password-stdin", help="Read passphrase from stdin."),
    ] = False,
) -> None:
    """Create a new encrypted keystore."""
    state = ctx.obj
    try:
        password = _io.read_password(
            password_stdin=password_stdin, confirm=True
        )
        Keystore.init(state.keystore_path, password)
        _io.emit_success("created keystore", detail=str(state.keystore_path))
        raise typer.Exit(0)
    except ValueError as exc:
        _io.emit_error(str(exc))
        raise typer.Exit(1) from exc
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("add-contact")
def add_contact_cmd(
    ctx: typer.Context,
    alias: Annotated[
        str, typer.Option("--alias", help="Contact display name.")
    ],
    pubkey: Annotated[
        Path, typer.Option("--pubkey", help="Contact SPKI PEM file.")
    ],
    notes: Annotated[
        str, typer.Option("--notes", help="Optional notes.")
    ] = "",
    verified: Annotated[
        bool,
        typer.Option("--verified", help="Mark verified out-of-band now."),
    ] = False,
    password_stdin: Annotated[
        bool,
        typer.Option("--password-stdin", help="Read passphrase from stdin."),
    ] = False,
) -> None:
    """Append a contact public key to the keystore."""
    state = ctx.obj
    try:
        import time

        # Adding a contact only appends public data; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        entry = store.add_contact(
            alias,
            pubkey.read_bytes(),
            notes=notes,
            verified_at=int(time.time() * 1000) if verified else None,
        )
        store.save()
        _io.emit_success(
            f"added contact {alias!r}", detail=_io.short_hash(entry.key_hash)
        )
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("verify-contact")
def verify_contact_cmd(
    ctx: typer.Context,
    alias: Annotated[
        str, typer.Option("--alias", help="Contact alias or key hash.")
    ],
    unverify: Annotated[
        bool,
        typer.Option(
            "--unverify", help="Clear the verification mark instead."
        ),
    ] = False,
) -> None:
    """Mark a contact verified out of band (or clear it with --unverify)."""
    state = ctx.obj
    try:
        # Verification touches only public metadata; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        entry = store.set_contact_verified(alias, verified=not unverify)
        store.save()
        action = "cleared verification for" if unverify else "verified"
        _io.emit_success(
            f"{action} contact {entry.alias!r}",
            detail=_io.short_hash(entry.key_hash),
        )
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("rename-contact")
def rename_contact_cmd(
    ctx: typer.Context,
    alias: Annotated[
        str, typer.Option("--alias", help="Current alias or key hash.")
    ],
    new_alias: Annotated[
        str, typer.Option("--to", help="New alias.")
    ],
) -> None:
    """Change a contact's alias."""
    state = ctx.obj
    try:
        # Renaming touches only public metadata; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        entry = store.rename_contact(alias, new_alias)
        store.save()
        _io.emit_success(
            f"renamed contact to {entry.alias!r}",
            detail=_io.short_hash(entry.key_hash),
        )
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("set-notes")
def set_notes_cmd(
    ctx: typer.Context,
    alias: Annotated[
        str, typer.Option("--alias", help="Contact alias or key hash.")
    ],
    notes: Annotated[
        str,
        typer.Option("--notes", help="New notes (empty string clears them)."),
    ],
) -> None:
    """Replace a contact's free-text notes."""
    state = ctx.obj
    try:
        # Notes are public metadata; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        entry = store.set_contact_notes(alias, notes)
        store.save()
        action = "set notes for" if notes else "cleared notes for"
        _io.emit_success(
            f"{action} contact {entry.alias!r}",
            detail=_io.short_hash(entry.key_hash),
        )
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("rename-key")
def rename_key_cmd(
    ctx: typer.Context,
    label: Annotated[
        str, typer.Option("--label", help="Current label or key hash.")
    ],
    new_label: Annotated[str, typer.Option("--to", help="New label.")],
) -> None:
    """Change an own key's label."""
    state = ctx.obj
    try:
        # Labels are public metadata; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        entry = store.rename_my_key(label, new_label)
        store.save()
        _io.emit_success(
            f"renamed key to {entry.label!r}",
            detail=_io.short_hash(entry.key_hash),
        )
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("set-key-expiry")
def set_key_expiry_cmd(
    ctx: typer.Context,
    label: Annotated[
        str, typer.Option("--label", help="Own key label or key hash.")
    ],
    expires: Annotated[
        str | None,
        typer.Option(
            "--expires",
            help="Rotation deadline as a date (YYYY-MM-DD) or ISO 8601 "
            "datetime; assumed UTC if no offset.",
        ),
    ] = None,
    clear: Annotated[
        bool,
        typer.Option("--clear", help="Remove the existing deadline instead."),
    ] = False,
) -> None:
    """Set or clear an own key's rotation deadline (a reminder, not enforced)."""
    state = ctx.obj
    try:
        if clear == (expires is not None):
            raise typer.BadParameter("provide exactly one of --expires or --clear")
        expires_ms = None if clear else _parse_expiry_to_ms(expires)  # type: ignore[arg-type]
        # The deadline is public metadata; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        entry = store.set_my_key_expiry(label, expires_ms)
        store.save()
        detail = (
            _io.short_hash(entry.key_hash)
            if clear
            else f"{_io.short_hash(entry.key_hash)} expires {expires}"
        )
        action = "cleared expiry for" if clear else "set expiry for"
        _io.emit_success(f"{action} key {entry.label!r}", detail=detail)
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("remove-contact")
def remove_contact_cmd(
    ctx: typer.Context,
    alias: Annotated[
        str, typer.Option("--alias", help="Contact alias or key hash.")
    ],
) -> None:
    """Delete a contact from the keystore."""
    state = ctx.obj
    try:
        # Removing a contact drops only public data; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        entry = store.remove_contact(alias)
        store.save()
        _io.emit_success(
            f"removed contact {entry.alias!r}",
            detail=_io.short_hash(entry.key_hash),
        )
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("remove-key")
def remove_key_cmd(
    ctx: typer.Context,
    label: Annotated[
        str, typer.Option("--label", help="Own key label or key hash.")
    ],
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Skip the confirmation prompt."),
    ] = False,
) -> None:
    """Delete an own key and its encrypted private key (irreversible)."""
    state = ctx.obj
    try:
        if not yes:
            _io.emit_stderr(
                f"This permanently deletes own key {label!r} and its private "
                "key. Messages encrypted to it can no longer be decrypted."
            )
            if not typer.confirm("Delete it?"):
                _io.emit_stderr("aborted")
                raise typer.Exit(1)
        # Deleting an entry needs no passphrase; file access already implies
        # control, and we are not decrypting anything.
        store = Keystore.load(state.keystore_path)
        entry = store.remove_my_key(label)
        store.save()
        _io.emit_success(
            f"removed key {entry.label!r}",
            detail=_io.short_hash(entry.key_hash),
        )
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("list-keys")
def list_keys_cmd(
    ctx: typer.Context,
    password_stdin: Annotated[
        bool,
        typer.Option("--password-stdin", help="Read passphrase from stdin."),
    ] = False,
) -> None:
    """List own keys (label, key_hash, created_at, expires_at)."""
    state = ctx.obj
    try:
        # Listing reads only public metadata; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        rows = [
            {
                "label": e.label,
                "key_hash": e.key_hash,
                "created_at": e.created_at,
                "expires_at": e.expires_at,
            }
            for e in store.list_my_keys()
        ]
        if state.json_output:
            _io.emit_json({"my_keys": rows})
        else:
            _io.emit_key_table(rows)
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("list-contacts")
def list_contacts_cmd(
    ctx: typer.Context,
    password_stdin: Annotated[
        bool,
        typer.Option("--password-stdin", help="Read passphrase from stdin."),
    ] = False,
) -> None:
    """List contacts (alias, key_hash, added_at, verified_at, notes)."""
    state = ctx.obj
    try:
        # Listing reads only public metadata; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        rows = [
            {
                "alias": c.alias,
                "key_hash": c.key_hash,
                "added_at": c.added_at,
                "verified_at": c.verified_at,
                "notes": c.notes,
            }
            for c in store.list_contacts()
        ]
        if state.json_output:
            _io.emit_json({"contacts": rows})
        else:
            _io.emit_contact_table(rows)
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("export-pubkey")
def export_pubkey_cmd(
    ctx: typer.Context,
    label: Annotated[
        str | None, typer.Option("--label", help="Own key label.")
    ] = None,
    key_hash: Annotated[
        str | None, typer.Option("--key-hash", help="Key hash.")
    ] = None,
    out_path: Annotated[
        str | None,
        typer.Option("--out", help="Write SPKI PEM here (default stdout)."),
    ] = None,
    password_stdin: Annotated[
        bool,
        typer.Option("--password-stdin", help="Read passphrase from stdin."),
    ] = False,
) -> None:
    """Write the SPKI PEM of an own key or contact."""
    state = ctx.obj
    try:
        query = label or key_hash
        if query is None:
            raise typer.BadParameter("provide --label or --key-hash")
        # Public keys are stored in clear; no passphrase needed.
        store = Keystore.load(state.keystore_path)
        pem = store.export_pubkey(query)
        _io.write_output(pem.encode("utf-8"), out_path)
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)


@keystore_app.command("hash-pubkey-pem")
def hash_pubkey_pem_cmd(
    ctx: typer.Context,
    in_path: Annotated[
        str | None,
        typer.Option("--in", help="SPKI PEM file, or - for stdin."),
    ] = None,
) -> None:
    """Print the key_hash of an SPKI PEM. No keystore required."""
    state = ctx.obj
    try:
        if in_path == "-" or in_path is None:
            import sys

            pem = sys.stdin.buffer.read()
        else:
            pem = Path(in_path).read_bytes()
        digest = keys.key_hash(keys.load_public_key(pem))
        if state.json_output:
            _io.emit_json({"key_hash": digest})
        else:
            _io.write_output((digest + "\n").encode("utf-8"), None)
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _fail(exc)
