from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer

from plaincloak.cli import _io
from plaincloak.cli.cmd_decrypt import decrypt_command
from plaincloak.cli.cmd_encrypt import encrypt_command
from plaincloak.cli.cmd_inspect import inspect_command
from plaincloak.cli.cmd_keygen import keygen_command
from plaincloak.cli.cmd_keystore import keystore_app
from plaincloak.cli.cmd_qr import qr_app

app = typer.Typer(
    name="plaincloak",
    help="PlainCloak v1: paste-anywhere authenticated public-key encryption.",
    no_args_is_help=True,
    add_completion=False,
)


@dataclass
class GlobalState:
    """Shared options resolved by the root callback.

    Attributes:
        keystore_path (Path): Where the keystore lives for this invocation.
        json_output (bool): Whether commands emit machine-readable JSON.
    """

    keystore_path: Path
    json_output: bool


@app.callback()
def main(
    ctx: typer.Context,
    keystore: Annotated[
        Path | None,
        typer.Option(
            "--keystore",
            help="Keystore path (default $PLAINCLOAK_KEYSTORE or "
            "~/.plaincloak/keystore.json).",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json", help="Emit machine-readable JSON where applicable."
        ),
    ] = False,
) -> None:
    """Resolve global options and attach them to the context."""
    _io.reconfigure_stdio()
    ctx.obj = GlobalState(
        keystore_path=keystore or _io.default_keystore_path(),
        json_output=json_output,
    )


app.command("keygen")(keygen_command)
app.command("encrypt")(encrypt_command)
app.command("decrypt")(decrypt_command)
app.command("inspect")(inspect_command)
app.add_typer(keystore_app, name="keystore")
app.add_typer(qr_app, name="qr")
