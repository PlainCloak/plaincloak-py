from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rich.box import Box

from plaincloak.exceptions import (
    InvalidKeyError,
    KeystoreFormatError,
    KeystoreLockedError,
    MalformedWireError,
    PlainCloakError,
    PlaintextTooLargeError,
    QRError,
)
from plaincloak.types import Outcome

_OUTCOME_EXIT_CODES: dict[Outcome, int] = {
    Outcome.VERIFIED: 0,
    Outcome.UNKNOWN_SENDER: 2,
    Outcome.SIGNATURE_INVALID: 3,
    Outcome.WRONG_RECIPIENT: 4,
    Outcome.DECRYPTION_FAILED: 5,
}


def reconfigure_stdio() -> None:
    """Force UTF-8 on stdout/stderr so Windows consoles do not mojibake.

    Safe to call once at CLI entry. No-ops on streams that do not support
    reconfiguration (e.g. already-wrapped test buffers).
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def default_keystore_path() -> Path:
    """Return the keystore path from the environment or the default home.

    Returns:
        Path: `$PLAINCLOAK_KEYSTORE` if set, else
            `~/.plaincloak/keystore.json`.
    """
    env = os.environ.get("PLAINCLOAK_KEYSTORE")
    if env:
        return Path(env)
    return Path.home() / ".plaincloak" / "keystore.json"


def read_password(
    *,
    password_stdin: bool,
    prompt: str = "Passphrase: ",
    confirm: bool = False,
) -> bytes:
    """Read a passphrase from stdin or an interactive prompt.

    Args:
        password_stdin (bool): When True, read exactly one line from stdin
            and strip the trailing newline. When False, prompt interactively
            via `getpass` (no echo).
        prompt (str): The interactive prompt text.
        confirm (bool): When True and reading interactively, prompt a second
            time and require both entries to match. Used when a new
            passphrase is being set (e.g. creating a keystore or its first
            key) to catch typos before they lock the keystore. Ignored under
            `--password-stdin`, where only one line is available.

    Raises:
        ValueError: If `confirm` is set, the input is interactive, and the
            two entries differ.

    Returns:
        bytes: The passphrase as UTF-8 bytes (never logged, never a flag).
    """
    if password_stdin:
        line = sys.stdin.readline()
        return line.rstrip("\n").rstrip("\r").encode("utf-8")
    first = getpass.getpass(prompt)
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise ValueError("passphrases did not match")
    return first.encode("utf-8")


def read_input(
    value: str | None, in_path: str | None, *, binary: bool = False
) -> bytes:
    """Resolve message/wire input from a literal, a file, or stdin.

    Args:
        value (str | None): A literal string value (e.g. `--message`), or
            `None` if not supplied.
        in_path (str | None): A file path, or `-` for stdin, or `None`.
        binary (bool): Unused placeholder for symmetry; all reads are bytes.

    Raises:
        ValueError: If neither a value nor an input path was provided.

    Returns:
        bytes: The resolved input bytes (UTF-8 for literal values).
    """
    if value is not None:
        return value.encode("utf-8")
    if in_path is None:
        raise ValueError("no input provided (expected a value, --in, or -)")
    if in_path == "-":
        return sys.stdin.buffer.read()
    return Path(in_path).read_bytes()


def write_output(data: bytes, out_path: str | None) -> None:
    """Write bytes to a file or stdout.

    Args:
        data (bytes): Payload to write.
        out_path (str | None): File path, `-`/`None` for stdout.
    """
    if out_path is None or out_path == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    Path(out_path).write_bytes(data)


def emit_json(payload: dict[str, Any]) -> None:
    """Print a JSON object to stdout (machine-readable mode)."""
    sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False))
    sys.stdout.write("\n")
    sys.stdout.flush()


def emit_stderr(message: str) -> None:
    """Print a human-readable line to stderr."""
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


# Values that read as "off" for a boolean env var. Anything else (including
# unset handled separately) is "on". This avoids the trap where `FOO=0` is
# truthy just because it is a non-empty string.
_FALSY_ENV = {"", "0", "false", "no", "off"}


def _env_flag(name: str) -> bool:
    """Interpret an env var as a boolean.

    Unset, empty, or one of `0/false/no/off` (case-insensitive) is False;
    any other value is True.

    Args:
        name (str): The environment variable name.

    Returns:
        bool: The resolved flag.
    """
    value = os.environ.get(name)
    if value is None:
        return False
    return value.strip().lower() not in _FALSY_ENV


def _ascii_only() -> bool:
    """Whether to avoid all Unicode glyphs and borders.

    Driven by `PLAINCLOAK_ASCII`. When set truthy, panels/tables use ASCII
    borders and the glyph helpers below return ASCII substitutes, so a fully
    ASCII terminal or log file sees no Unicode.
    """
    return _env_flag("PLAINCLOAK_ASCII")


# Unicode glyph -> ASCII fallback. Resolved per call via _glyph so the env
# var can be toggled at runtime (e.g. in tests).
_GLYPH_FALLBACK: dict[str, str] = {
    "…": "...",
    "·": "|",
    "✓": "[ok]",
    "—": "-",
}


def _glyph(unicode_glyph: str) -> str:
    """Return a glyph, or its ASCII fallback when `PLAINCLOAK_ASCII` is set."""
    if _ascii_only():
        return _GLYPH_FALLBACK[unicode_glyph]
    return unicode_glyph


def _box_style() -> Box:
    """Return the Rich box style for panels and tables.

    Defaults to rounded Unicode borders. Set `PLAINCLOAK_ASCII` (any value)
    to fall back to pure ASCII for consoles that render Unicode boxes poorly.
    """
    from rich import box

    if _ascii_only():
        return box.ASCII
    return box.ROUNDED


def short_hash(key_hash: str) -> str:
    """Abbreviate a 64-char key hash for display as `3f9a1c…b2`.

    Full hashes stay available via `--json`; this is for human-facing tables
    and panels only. Set `PLAINCLOAK_FULL_HASH` truthy to keep the full hash
    in human output too. Returns the input unchanged when it is too short to
    abbreviate.

    Args:
        key_hash (str): The full hex key hash.

    Returns:
        str: The abbreviated form, or the full hash if `PLAINCLOAK_FULL_HASH`
            is set or the input is 10 chars or shorter.
    """
    if _env_flag("PLAINCLOAK_FULL_HASH") or len(key_hash) <= 10:
        return key_hash
    return f"{key_hash[:6]}{_glyph('…')}{key_hash[-2:]}"


def emit_success(message: str, *, detail: str | None = None) -> None:
    """Print a green check-marked confirmation line to stderr.

    Args:
        message (str): The action summary, e.g. "stored key 'alice'".
        detail (str | None): Optional dim trailing detail such as a short
            hash or a path.
    """
    from rich.console import Console
    from rich.text import Text

    line = Text(f"{_glyph('✓')} ", style="bold green")
    line.append(message)
    if detail:
        line.append(f"  {detail}", style="dim")
    Console(stderr=True).print(line)


def emit_error(message: str) -> None:
    """Print an error line to stderr in red (when stderr is a terminal).

    Rich strips the color automatically for a non-terminal stderr, so a
    captured or redirected error stays plain text.

    Args:
        message (str): The error text (without the `error:` prefix).
    """
    from rich.console import Console

    Console(stderr=True).print(f"error: {message}", style="bold red")


def emit_plaintext(text: str, out_path: str | None) -> None:
    """Deliver decrypted plaintext, boxed only for an interactive stdout.

    A file (`--out`) or a piped/redirected stdout receives the raw UTF-8
    bytes with nothing added, preserving the spec contract that plaintext
    goes to stdout verbatim. Only an interactive stdout gets a Rich panel
    for readability - the box characters never enter a pipe.

    Args:
        text (str): The decrypted plaintext.
        out_path (str | None): `--out` target; file path, or `-`/`None`
            for stdout.
    """
    to_stdout = out_path is None or out_path == "-"
    if to_stdout and sys.stdout.isatty():
        from rich.console import Console
        from rich.panel import Panel

        Console().print(
            Panel(
                text, title="message", title_align="left", box=_box_style()
            )
        )
        return
    write_output(text.encode("utf-8"), out_path)


_OUTCOME_STYLE: dict[Outcome, str] = {
    Outcome.VERIFIED: "bold green",
    Outcome.UNKNOWN_SENDER: "bold yellow",
    Outcome.SIGNATURE_INVALID: "bold red",
    Outcome.WRONG_RECIPIENT: "bold red",
    Outcome.DECRYPTION_FAILED: "bold red",
}

_OUTCOME_NOTE: dict[Outcome, str] = {
    Outcome.VERIFIED: "signature verified",
    Outcome.UNKNOWN_SENDER: "sender not in contacts - authenticity unverified",
    Outcome.SIGNATURE_INVALID: "SIGNATURE INVALID - do not trust this message",
    Outcome.WRONG_RECIPIENT: "not the intended recipient - no plaintext",
    Outcome.DECRYPTION_FAILED: "decryption failed - no plaintext",
}


def _format_timestamp(timestamp_ms: int) -> str:
    """Render a Unix-ms timestamp as `YYYY-MM-DD HH:MM:SS UTC (raw)`."""
    from datetime import datetime, timezone

    try:
        dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return str(timestamp_ms)
    return f"{dt:%Y-%m-%d %H:%M:%S} UTC ({timestamp_ms})"


def _format_ts_short(timestamp_ms: int | None) -> str:
    """Render a Unix-ms timestamp compactly as `YYYY-MM-DD HH:MM UTC`.

    Used in list tables where the raw value and seconds would be noise.
    Returns an em dash for a missing timestamp and the raw value if it is
    out of range.
    """
    if timestamp_ms is None:
        return _glyph("—")
    from datetime import datetime, timezone

    try:
        dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return str(timestamp_ms)
    return f"{dt:%Y-%m-%d %H:%M} UTC"


def emit_envelope_report(
    *,
    suite: str,
    message_id: str,
    timestamp_ms: int,
    sender_key_hash: str,
    recipient_key_hash: str,
    payload_len: int,
    signature_len: int,
    body_len: int,
) -> None:
    """Print envelope metadata as a Rich panel to stderr.

    Human output is diagnostic and always goes to stderr; pipe consumers use
    `--json` (stdout) instead. Mirrors the decrypt report layout, minus any
    trust outcome since no keys are involved. Rich drops styling for a
    non-interactive stderr and honors `NO_COLOR`.

    Args:
        suite (str): Suite identifier.
        message_id (str): Envelope message id.
        timestamp_ms (int): Envelope timestamp (Unix milliseconds).
        sender_key_hash (str): Sender key hash (shown abbreviated).
        recipient_key_hash (str): Recipient key hash (shown abbreviated).
        payload_len (int): Compressed payload size in bytes.
        signature_len (int): Signature size in bytes.
        body_len (int): Decompressed body size in bytes.
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    header = Text("envelope", style="bold")
    header.append("  no keys used", style="dim")

    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", justify="right")
    table.add_column(overflow="fold")
    table.add_row("from", short_hash(sender_key_hash))
    table.add_row("to", short_hash(recipient_key_hash))
    table.add_row("suite", suite)
    table.add_row("message id", message_id)
    table.add_row("timestamp", _format_timestamp(timestamp_ms))
    table.add_row(
        "sizes",
        f"payload {payload_len} B {_glyph('·')} sig {signature_len} B "
        f"{_glyph('·')} body {body_len} B",
    )

    console = Console(stderr=True)
    console.print()
    console.print(
        Panel(table, title=header, title_align="left", box=_box_style())
    )


def emit_key_table(rows: list[dict[str, Any]]) -> None:
    """Render own-key rows as a bordered table to stderr.

    Human output is diagnostic and goes to stderr; pipe consumers use
    `--json` (stdout) instead.

    Args:
        rows (list[dict]): Each row has `label`, `key_hash`, `created_at`,
            and `expires_at`. An empty list prints a dim placeholder.
    """
    from rich.console import Console
    from rich.table import Table

    console = Console(stderr=True)
    if not rows:
        console.print("(no keys yet)", style="dim")
        return

    table = Table(title="my keys", title_justify="left", box=_box_style())
    table.add_column("label", style="cyan", no_wrap=True)
    table.add_column("key hash", no_wrap=True)
    table.add_column("created", no_wrap=True)
    table.add_column("expires", no_wrap=True)
    for row in rows:
        table.add_row(
            row["label"],
            short_hash(row["key_hash"]),
            _format_ts_short(row["created_at"]),
            _format_ts_short(row["expires_at"]),
        )
    console.print(table)


def emit_contact_table(rows: list[dict[str, Any]]) -> None:
    """Render contact rows as a bordered table to stderr.

    Human output is diagnostic and goes to stderr; pipe consumers use
    `--json` (stdout) instead.

    Args:
        rows (list[dict]): Each row has `alias`, `key_hash`, `added_at`, and
            `verified_at`. A present `verified_at` shows a green check with
            its date; otherwise the row is marked unverified. An empty list
            prints a dim placeholder.
    """
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    console = Console(stderr=True)
    if not rows:
        console.print("(no contacts yet)", style="dim")
        return

    # The notes column only appears when at least one contact has notes, so
    # the common case stays narrow.
    show_notes = any(row.get("notes") for row in rows)

    table = Table(title="contacts", title_justify="left", box=_box_style())
    table.add_column("alias", style="cyan", no_wrap=True)
    table.add_column("key hash", no_wrap=True)
    table.add_column("added", no_wrap=True)
    table.add_column("verified", no_wrap=True)
    if show_notes:
        table.add_column("notes", overflow="fold")
    for row in rows:
        verified_at = row["verified_at"]
        if verified_at:
            verified = Text(
                f"{_glyph('✓')} {_format_ts_short(verified_at)}",
                style="green",
            )
        else:
            verified = Text("unverified", style="dim")
        cells = [
            row["alias"],
            short_hash(row["key_hash"]),
            _format_ts_short(row["added_at"]),
            verified,
        ]
        if show_notes:
            cells.append(row.get("notes", ""))
        table.add_row(*cells)
    console.print(table)


def emit_decrypt_report(
    *,
    outcome: Outcome,
    suite: str,
    sender_key_hash: str,
    recipient_key_hash: str,
    message_id: str,
    timestamp_ms: int,
    had_plaintext: bool,
    sender_name: str | None = None,
    recipient_name: str | None = None,
) -> None:
    """Print a human-readable decrypt report to stderr via Rich.

    The plaintext (if any) has already gone to stdout. This block is
    diagnostic metadata only, so it never pollutes a piped plaintext.
    Rich's stderr `Console` strips styling automatically when stderr is not
    an interactive terminal and honors `NO_COLOR`.

    Args:
        outcome (Outcome): The decrypt outcome.
        suite (str): Body suite identifier.
        sender_key_hash (str): Body `s` field.
        recipient_key_hash (str): Body `r` field.
        message_id (str): Body `i` field.
        timestamp_ms (int): Body `t` field (Unix milliseconds).
        had_plaintext (bool): Whether plaintext was written to stdout.
        sender_name (str | None): Contact alias for the sender, if known.
            Shown before the hash as `alias (hash)`.
        recipient_name (str | None): Own-key label for the recipient, if
            known. Shown before the hash as `label (hash)`.
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    def _identity(name: str | None, key_hash: str) -> str:
        short = short_hash(key_hash)
        return f"{name} ({short})" if name else short

    style = _OUTCOME_STYLE[outcome]
    header = Text(outcome.value, style=style)
    header.append(f"  {_OUTCOME_NOTE[outcome]}", style="dim")

    table = Table.grid(padding=(0, 2))
    table.add_column(style="cyan", justify="right")
    table.add_column(overflow="fold")
    table.add_row("from", _identity(sender_name, sender_key_hash))
    table.add_row("to", _identity(recipient_name, recipient_key_hash))
    table.add_row("suite", suite)
    table.add_row("message id", message_id)
    table.add_row("timestamp", _format_timestamp(timestamp_ms))
    if not had_plaintext:
        table.add_row("plaintext", "(none produced)")

    console = Console(stderr=True)
    console.print()
    console.print(
        Panel(
            table,
            title=header,
            title_align="left",
            border_style=style,
            box=_box_style(),
        )
    )


def outcome_exit_code(outcome: Outcome) -> int:
    """Map a decrypt `Outcome` to its CLI exit code."""
    return _OUTCOME_EXIT_CODES[outcome]


def error_exit_code(exc: PlainCloakError) -> int:
    """Map a library exception to its CLI exit code.

    Args:
        exc (PlainCloakError): The raised library error.

    Returns:
        int: 6 for malformed-wire family, 7 for producer key/size errors,
            8 for keystore lock/format errors, 9 for QR transport errors,
            1 for any other library error.
    """
    if isinstance(exc, MalformedWireError):
        return 6
    if isinstance(exc, (PlaintextTooLargeError, InvalidKeyError)):
        return 7
    if isinstance(exc, (KeystoreLockedError, KeystoreFormatError)):
        return 8
    if isinstance(exc, QRError):
        return 9
    return 1
