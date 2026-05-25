from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from plaincloak.api import decode_qr, encode_qr
from plaincloak.cli import _io
from plaincloak.exceptions import PlainCloakError

qr_app = typer.Typer(
    name="qr",
    help="Single-QR transport (optional `[qr]` extra).",
    no_args_is_help=True,
)


def encode_command(
    ctx: typer.Context,
    wire: Annotated[
        str | None,
        typer.Argument(help="Wire string, or omit and use --in / -."),
    ] = None,
    in_path: Annotated[
        str | None,
        typer.Option("--in", help="Read wire from file, or - for stdin."),
    ] = None,
    out_path: Annotated[
        Path | None,
        typer.Option("--out", help="Write the QR PNG to this path."),
    ] = None,
    error_correction: Annotated[
        str,
        typer.Option("--ec", help="Error-correction level: L, M, Q, or H."),
    ] = "M",
) -> None:
    """Encode a wire string into a single QR PNG."""
    try:
        if out_path is None:
            raise typer.BadParameter("provide --out to name the QR PNG")
        wire_text = _read_wire(wire, in_path)
        image = encode_qr(wire_text, error_correction=error_correction)
        image.save(out_path)
        _io.emit_stderr(f"wrote QR to {out_path}")
        raise typer.Exit(0)
    except (PlainCloakError, ValueError) as exc:
        _io.emit_error(str(exc))
        code = _io.error_exit_code(exc) if isinstance(exc, PlainCloakError) else 1
        raise typer.Exit(code) from exc


def decode_command(
    ctx: typer.Context,
    in_path: Annotated[
        Path | None,
        typer.Option("--in", help="Read the QR image (PNG / JPG) from here."),
    ] = None,
    out_path: Annotated[
        str | None,
        typer.Option("--out", help="Write wire to file (default stdout)."),
    ] = None,
) -> None:
    """Decode a wire string from a saved QR image and print it to stdout."""
    try:
        if in_path is None:
            raise typer.BadParameter("provide --in to name the QR image")
        wire_text = decode_qr(in_path)
        _io.write_output(wire_text.encode("utf-8"), out_path)
        if out_path not in (None, "-"):
            _io.emit_stderr(f"wrote wire to {out_path}")
        raise typer.Exit(0)
    except PlainCloakError as exc:
        _io.emit_error(str(exc))
        raise typer.Exit(_io.error_exit_code(exc)) from exc


def _read_wire(wire: str | None, in_path: str | None) -> str:
    """Resolve the wire string from an argument, a file, or stdin."""
    if wire is not None and wire != "-":
        return wire.strip()
    if wire == "-" or in_path == "-":
        return sys.stdin.buffer.read().decode("utf-8").strip()
    if in_path is not None:
        return Path(in_path).read_text(encoding="utf-8").strip()
    raise ValueError("no wire provided (expected an argument, --in, or -)")


qr_app.command("encode")(encode_command)
qr_app.command("decode")(decode_command)
