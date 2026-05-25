from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from plaincloak.api import parse_envelope
from plaincloak.cli import _io
from plaincloak.exceptions import PlainCloakError


def inspect_command(
    ctx: typer.Context,
    wire: Annotated[
        str | None,
        typer.Argument(help="Wire string, or omit and use --in / -."),
    ] = None,
    in_path: Annotated[
        str | None,
        typer.Option("--in", help="Read wire from file, or - for stdin."),
    ] = None,
) -> None:
    """Print suite, message id, timestamp, key hashes, and field lengths."""
    state = ctx.obj
    try:
        if wire is not None and wire != "-":
            wire_text = wire.strip()
        elif wire == "-" or in_path == "-":
            import sys

            wire_text = sys.stdin.buffer.read().decode("utf-8").strip()
        elif in_path is not None:
            wire_text = Path(in_path).read_text(encoding="utf-8").strip()
        else:
            raise typer.BadParameter("provide a wire argument, --in, or -")

        info = parse_envelope(wire_text)
        payload = {
            "suite": info.suite,
            "message_id": info.message_id,
            "timestamp_ms": info.timestamp_ms,
            "sender_key_hash": info.sender_key_hash,
            "recipient_key_hash": info.recipient_key_hash,
            "payload_len": info.payload_len,
            "signature_len": info.signature_len,
            "body_len": info.body_len,
        }
        if state.json_output:
            _io.emit_json(payload)
        else:
            _io.emit_envelope_report(
                suite=info.suite,
                message_id=info.message_id,
                timestamp_ms=info.timestamp_ms,
                sender_key_hash=info.sender_key_hash,
                recipient_key_hash=info.recipient_key_hash,
                payload_len=info.payload_len,
                signature_len=info.signature_len,
                body_len=info.body_len,
            )
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _io.emit_error(str(exc))
        raise typer.Exit(_io.error_exit_code(exc)) from exc
