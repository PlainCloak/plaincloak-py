from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_PW = "correct horse battery staple"


def _run(args: list[str], *, stdin: str | None = None, env=None):
    return subprocess.run(
        [sys.executable, "-m", "plaincloak", *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )


def test_module_help_lists_every_subcommand() -> None:
    result = _run(["--help"])
    assert result.returncode == 0
    for cmd in ("keygen", "encrypt", "decrypt", "inspect", "keystore"):
        assert cmd in result.stdout


def test_full_shell_roundtrip(tmp_path: Path) -> None:
    keystore = tmp_path / "keystore.json"
    base = ["--keystore", str(keystore)]

    # 1. keygen into the keystore.
    gen = _run(
        [*base, "keygen", "--label", "alice", "--bits", "2048", "--password-stdin"],
        stdin=f"{_PW}\n",
    )
    assert gen.returncode == 0, gen.stderr

    # 2. derive alice's key hash from the exported pubkey.
    export = _run(
        [*base, "keystore", "export-pubkey", "--label", "alice", "--password-stdin"],
        stdin=f"{_PW}\n",
    )
    assert export.returncode == 0, export.stderr
    pub_pem = tmp_path / "alice-pub.pem"
    pub_pem.write_text(export.stdout, encoding="utf-8")

    key_hash = _run(
        [*base, "keystore", "hash-pubkey-pem", "--in", str(pub_pem)]
    )
    assert key_hash.returncode == 0, key_hash.stderr
    alice_hash = key_hash.stdout.strip()
    assert len(alice_hash) == 64

    # 3. add alice as her own trusted contact so the signature verifies.
    add = _run(
        [
            *base,
            "keystore",
            "add-contact",
            "--alias",
            "alice",
            "--pubkey",
            str(pub_pem),
            "--password-stdin",
        ],
        stdin=f"{_PW}\n",
    )
    assert add.returncode == 0, add.stderr

    # 4. encrypt to alice from alice.
    enc = _run(
        [
            *base,
            "encrypt",
            "--to",
            alice_hash,
            "--from",
            "alice",
            "--message",
            "hi",
            "--password-stdin",
        ],
        stdin=f"{_PW}\n",
    )
    assert enc.returncode == 0, enc.stderr
    wire = enc.stdout.strip()
    assert wire.startswith("PLAINCLOAK:v1:BR:")

    # 5. decrypt: password line first, wire second (shared stdin).
    dec = _run(
        [*base, "decrypt", "-", "--password-stdin"],
        stdin=f"{_PW}\n{wire}\n",
    )
    assert dec.returncode == 0, dec.stderr
    assert dec.stdout.strip() == "hi"
    assert "verified" in dec.stderr


def test_inspect_needs_no_keys(tmp_path: Path) -> None:
    keystore = tmp_path / "ks.json"
    base = ["--keystore", str(keystore)]
    _run(
        [*base, "keygen", "--label", "a", "--bits", "2048", "--password-stdin"],
        stdin=f"{_PW}\n",
    )
    export = _run(
        [*base, "keystore", "export-pubkey", "--label", "a", "--password-stdin"],
        stdin=f"{_PW}\n",
    )
    pub = tmp_path / "a.pem"
    pub.write_text(export.stdout, encoding="utf-8")
    h = _run([*base, "keystore", "hash-pubkey-pem", "--in", str(pub)]).stdout.strip()
    enc = _run(
        [
            *base,
            "encrypt",
            "--to",
            h,
            "--from",
            "a",
            "--message",
            "x",
            "--password-stdin",
        ],
        stdin=f"{_PW}\n",
    )
    wire = enc.stdout.strip()

    info = _run(["inspect", wire])
    assert info.returncode == 0, info.stderr
    assert "RSA-OAEP-AES256GCM-SHA256" in info.stderr


def test_wrong_recipient_exit_code_4(tmp_path: Path) -> None:
    base_a = ["--keystore", str(tmp_path / "a.json")]
    base_b = ["--keystore", str(tmp_path / "b.json")]

    _run(
        [*base_a, "keygen", "--label", "a", "--bits", "2048", "--password-stdin"],
        stdin=f"{_PW}\n",
    )
    _run(
        [*base_b, "keygen", "--label", "b", "--bits", "2048", "--password-stdin"],
        stdin=f"{_PW}\n",
    )
    ea = _run(
        [*base_a, "keystore", "export-pubkey", "--label", "a", "--password-stdin"],
        stdin=f"{_PW}\n",
    )
    pub_a = tmp_path / "a.pem"
    pub_a.write_text(ea.stdout, encoding="utf-8")
    ha = _run(
        [*base_a, "keystore", "hash-pubkey-pem", "--in", str(pub_a)]
    ).stdout.strip()
    enc = _run(
        [
            *base_a,
            "encrypt",
            "--to",
            ha,
            "--from",
            "a",
            "--message",
            "secret",
            "--password-stdin",
        ],
        stdin=f"{_PW}\n",
    )
    wire = enc.stdout.strip()

    # b's keystore has no key matching a's recipient hash -> wrong-recipient.
    dec = _run(
        [*base_b, "decrypt", "-", "--password-stdin"],
        stdin=f"{_PW}\n{wire}\n",
    )
    assert dec.returncode == 4, dec.stderr
    assert dec.stdout.strip() == ""


def test_keygen_wrong_passphrase_on_existing_keystore(tmp_path: Path) -> None:
    base = ["--keystore", str(tmp_path / "ks.json")]
    first = _run(
        [*base, "keygen", "--label", "a", "--bits", "2048", "--password-stdin"],
        stdin=f"{_PW}",
    )
    assert first.returncode == 0, first.stderr

    # Wrong passphrase for a second key must be rejected up front (exit 8),
    # not silently written under a different passphrase.
    second = _run(
        [*base, "keygen", "--label", "b", "--bits", "2048", "--password-stdin"],
        stdin="not the same passphrase",
    )
    assert second.returncode == 8, second.stderr

    # Original key still openable with the original passphrase.
    ls = _run(
        [*base, "keystore", "list-keys"],
    )
    assert ls.returncode == 0, ls.stderr
