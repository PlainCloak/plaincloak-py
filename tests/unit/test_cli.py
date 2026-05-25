from __future__ import annotations

import pytest
from typer.testing import CliRunner

from plaincloak.cli.main import app

runner = CliRunner()


class TestHelp:
    """`--help` works at the root and for every subcommand."""

    def test_root_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "keygen" in result.output
        assert "encrypt" in result.output
        assert "decrypt" in result.output
        assert "inspect" in result.output
        assert "keystore" in result.output
        assert "qr" in result.output

    def test_each_command_help(self) -> None:
        for cmd in ("keygen", "encrypt", "decrypt", "inspect"):
            result = runner.invoke(app, [cmd, "--help"])
            assert result.exit_code == 0, cmd

    def test_qr_subcommands_registered(self) -> None:
        result = runner.invoke(app, ["qr", "--help"])
        assert result.exit_code == 0
        assert "encode" in result.output
        assert "decode" in result.output

    def test_keystore_subcommands_registered(self) -> None:
        result = runner.invoke(app, ["keystore", "--help"])
        assert result.exit_code == 0
        for sub in (
            "init",
            "add-contact",
            "verify-contact",
            "rename-contact",
            "set-notes",
            "remove-contact",
            "rename-key",
            "set-key-expiry",
            "remove-key",
            "list-keys",
            "list-contacts",
            "export-pubkey",
            "hash-pubkey-pem",
        ):
            assert sub in result.output


class TestExitCodes:
    """Representative failure paths map to the documented exit codes."""

    def test_malformed_wire_is_code_6(self) -> None:
        result = runner.invoke(
            app, ["inspect", "not-a-plaincloak-wire"]
        )
        assert result.exit_code == 6

    def test_oversized_qr_is_code_9(self) -> None:
        # A wire past the version-40 M-level capacity maps QRError -> code 9.
        from plaincloak.api import max_qr_wire_bytes

        oversized = "x" * (max_qr_wire_bytes("M") + 1)
        result = runner.invoke(app, ["qr", "encode", oversized, "--out", "x.png"])
        assert result.exit_code == 9

    def test_missing_keystore_is_code_1(self, tmp_path) -> None:
        # list-keys on a non-existent keystore -> KeystoreError -> code 1.
        result = runner.invoke(
            app,
            [
                "--keystore",
                str(tmp_path / "nope.json"),
                "keystore",
                "list-keys",
                "--password-stdin",
            ],
            input="pw\n",
        )
        assert result.exit_code == 1

    def test_no_args_shows_help_not_crash(self) -> None:
        # no_args_is_help shows usage and exits 2 (click convention).
        result = runner.invoke(app, [])
        assert result.exit_code == 2
        assert "Usage" in result.output or "Commands" in result.output


class TestReadPasswordConfirm:
    """Interactive confirm requires both entries to match."""

    def test_confirm_mismatch_raises(self, monkeypatch) -> None:
        from plaincloak.cli import _io

        answers = iter(["first", "second"])
        monkeypatch.setattr(
            _io.getpass, "getpass", lambda *a, **k: next(answers)
        )
        with pytest.raises(ValueError, match="did not match"):
            _io.read_password(password_stdin=False, confirm=True)

    def test_confirm_match_returns_bytes(self, monkeypatch) -> None:
        from plaincloak.cli import _io

        monkeypatch.setattr(
            _io.getpass, "getpass", lambda *a, **k: "same"
        )
        assert _io.read_password(
            password_stdin=False, confirm=True
        ) == b"same"
