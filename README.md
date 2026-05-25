# PlainCloak

[![CI](https://github.com/PlainCloak/plaincloak-py/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/PlainCloak/plaincloak-py/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/plaincloak.svg)](https://pypi.org/project/plaincloak/)
[![Python versions](https://img.shields.io/pypi/pyversions/plaincloak.svg)](https://pypi.org/project/plaincloak/)

Python reference implementation of the [PlainCloak v1](https://github.com/PlainCloak/plaincloak-spec) protocol: text-safe, authenticated public-key encryption you can paste into any chat app.

A PlainCloak message is a single line:

```
PLAINCLOAK:v1:BR:4dHRrngWcgate3V2PFZwBFZFXfOSeE8w...
```

It carries everything a recipient needs to decrypt and verify it - no server, no key exchange protocol, no account.

The package ships both a Python library and a `plaincloak` command line tool, so you can use it from your own code or straight from the shell.

## Install

```
pip install plaincloak              # base: PBKDF2 keystore fallback
pip install plaincloak[keystore]    # adds Argon2id KDF (recommended)
pip install plaincloak[qr]          # adds single-QR transport
```

Requires Python 3.10+. The base install is fully functional. Both extras are optional: `[keystore]` upgrades the keystore KDF from PBKDF2-SHA256 to Argon2id, and `[qr]` adds the QR encode/decode helpers (see below).

Prefer `[keystore]` whenever you can. The keystore encrypts your private keys with a key derived from your passphrase, so if the file is stolen, an attacker brute-forces that passphrase offline and the KDF's cost per guess is the real defense. PBKDF2 is CPU-only and cheap to parallelize on GPUs/ASICs; Argon2id is memory-hard - it forces ~19 MiB per guess, neutralizing that parallelism, and is the OWASP/RFC 9106 recommendation. PBKDF2 stays as a stdlib-only fallback so the base install needs no native dependency.

The `[qr]` extra pulls in `qrcode`, `Pillow`, and `pyzbar`. `pyzbar` wraps the native zbar library, bundled in the Windows/macOS wheels; on Linux install it first (`apt-get install libzbar0`).

## Library quickstart

The top-level `plaincloak` module is the whole API. The core is a handful of
stateless functions (`generate_keypair`, `encrypt`, `decrypt`, `parse_envelope`, ...)
that work on plain `cryptography` RSA objects, so you own key storage and
trust. If you want the same encrypted-at-rest keystore the CLI uses (private keys
plus contacts, all in one passphrase-protected file), the `Keystore` class is
exported too.

The [`notebooks/quickstart.ipynb`](notebooks/quickstart.ipynb) notebook walks through all major features interactively.

```python
import plaincloak

alice = plaincloak.generate_keypair(bits=2048)   # sender
bob = plaincloak.generate_keypair(bits=4096)     # recipient

wire = plaincloak.encrypt(
    "meet at the usual place",
    recipient_public_key=bob.public_key,
    sender_private_key=alice.private_key,
)
# wire -> "PLAINCLOAK:v1:BR:..."  paste this anywhere

result = plaincloak.decrypt(
    wire,
    own_private_keys=[bob.private_key],
    trusted_senders={alice.key_hash: alice.public_key},
)
result.outcome      # Outcome.VERIFIED
result.plaintext    # "meet at the usual place"
```

`decrypt` never raises on a cryptographic outcome. It returns one of five
`Outcome` values; `signature-invalid` and `unknown-sender` still deliver the
plaintext (paired with the warning) so the caller decides what to trust.
Only structural failures (bad envelope, schema, unknown suite) raise a
`MalformedWireError`.

| Outcome | Meaning | `plaintext` present? |
|---|---|---|
| `VERIFIED` | Signature valid, sender trusted | Yes |
| `UNKNOWN_SENDER` | Decrypted OK but sender not in `trusted_senders` | Yes |
| `SIGNATURE_INVALID` | Decrypted OK but signature verification failed | Yes |
| `WRONG_RECIPIENT` | No matching private key | No |
| `DECRYPTION_FAILED` | Matching key found but decryption failed | No |

Inspect a message without any keys:

```python
info = plaincloak.parse_envelope(wire)
info.suite              # Suite.RSA_OAEP_AES256GCM_SHA256
info.message_id         # "b5ca2440-fbb0-4e33-83af-4222bf2b0bf5"
info.timestamp_ms       # 1746789123456
info.sender_key_hash    # 64-char hex - identify who sent it
info.recipient_key_hash # 64-char hex - identify who it's for
info.payload_len        # compressed payload size in bytes
info.body_len           # decompressed JSON body size in bytes
```

The default suite is the hybrid `RSA-OAEP-AES256GCM-SHA256` (no plaintext
length cap). Pass `suite=plaincloak.Suite.RSA_OAEP_SHA256` for the direct
suite (capped at `modulus - 66` bytes).

With the `[qr]` extra, a wire string round-trips through a single QR image
(`encode_qr` / `decode_qr`), handy for air-gapped or screen-to-camera transfer:

```python
plaincloak.encode_qr(wire).save("msg.png")   # write a PNG
plaincloak.decode_qr("msg.png")              # read it back -> the same wire
```

This is a transport convenience layered on the finished wire string; it never
touches the format or crypto. A typical wire fits one QR; an oversized one (a
long hybrid message) raises `MessageTooLargeForQRError`. `max_qr_wire_bytes()`
returns the capacity for a given error-correction level.

## CLI quickstart

Installing the package ships a `plaincloak` command line tool (also runnable as
`python -m plaincloak`). It manages an encrypted keystore for your private keys
and contacts, and does the encrypt/decrypt/inspect work the library exposes.

The walkthrough below follows Alice sending a signed, encrypted message to Bob.
Each person has their own keystore holding their private keys and their
contacts' public keys. Here we give each a separate keystore file with
`--keystore` so the whole thing runs on one machine; in real use you can drop the
flag and it falls back to the default keystore (`~/.plaincloak/keystore.json`).

```sh
# --- Alice's machine ---
# Generate Alice's keypair. This creates her keystore and prompts for a
# passphrase that encrypts her private key at rest.
plaincloak --keystore alice.json keygen --label alice

# Export her public key so she can hand it to Bob (PEM is safe to share).
plaincloak --keystore alice.json keystore export-pubkey --label alice --out alice-pub.pem

# --- Bob's machine ---
# Bob does the same: his own keypair and keystore.
plaincloak --keystore bob.json keygen --label bob
plaincloak --keystore bob.json keystore export-pubkey --label bob --out bob-pub.pem

# --- They exchange the two .pem files out of band, then add each other ---
plaincloak --keystore alice.json keystore add-contact --alias bob --pubkey bob-pub.pem
plaincloak --keystore bob.json keystore add-contact --alias alice --pubkey alice-pub.pem

# --- Alice encrypts a message to Bob, signed with her own key ---
plaincloak --keystore alice.json encrypt --to bob --from alice \
    --message "meet at the usual place" --out msg.txt
# msg.txt now holds one line: PLAINCLOAK:v1:BR:...  Alice pastes it anywhere.

# --- Bob decrypts. Exit 0 and outcome VERIFIED means it really came from Alice ---
plaincloak --keystore bob.json decrypt --in msg.txt

# Anyone can read the public metadata without any key:
plaincloak inspect --in msg.txt
```

Because Bob added Alice as a contact, `decrypt` reports `VERIFIED` (exit 0). If
he had not, he would still get the plaintext but with `UNKNOWN_SENDER` (exit 2),
since the message is decryptable but the signer is not yet trusted.

### Verifying contacts

Adding a contact stores their public key but does not prove it really belongs to
them (a man-in-the-middle could have swapped it). Once you confirm the key out of
band mark it:

```sh
plaincloak keystore verify-contact --alias bob              # stamp it verified
plaincloak keystore verify-contact --alias bob --unverify   # undo
```

The `verified` column in `keystore list-contacts` reflects this. It is a trust
reminder for you; it does not change decrypt outcomes (those only check the
signature against the key you hold).

Other editable fields have their own commands:

```sh
plaincloak keystore rename-contact --alias bob --to bobby
plaincloak keystore set-notes --alias bob --notes "met at the conf"   # shown in list-contacts
plaincloak keystore remove-contact --alias bob

plaincloak keystore rename-key --label alice --to alice-personal
plaincloak keystore set-key-expiry --label alice --expires 2027-01-01   # rotation reminder
plaincloak keystore set-key-expiry --label alice --clear
plaincloak keystore remove-key --label alice                            # irreversible, prompts
```

### QR transport (optional)

With the `[qr]` extra installed, the `qr` sub-app turns a wire string into a
single QR PNG and back - useful for moving a message to an air-gapped machine by
camera. Encode and decode pipe straight into the rest of the CLI:

```sh
plaincloak --keystore alice.json encrypt --to bob --from alice \
    --message "meet at the usual place" | plaincloak qr encode --out msg.png -
# scan / transfer msg.png, then on the other side:
plaincloak qr decode --in msg.png | plaincloak --keystore bob.json decrypt -
```

Decoding reads a saved image file. An oversized wire fails with exit 9 rather than producing a truncated code; split
the message or use a smaller key. Without the `[qr]` extra the `qr` commands exit
9 with a clear message and the rest of the CLI is unaffected.

### Output, JSON, and pipes

Human-readable output (the decrypt report, `inspect`, `list-*` tables) goes to
stderr; only the decrypted plaintext goes to stdout. So `decrypt --in msg.txt`
pipes clean plaintext, and you read the result from the exit code (see below).
For a machine-readable result, add the global `--json` flag (before the
subcommand) - it prints one JSON object to stdout with the outcome, plaintext,
and metadata:

```sh
plaincloak --json decrypt --in msg.txt | jq .outcome
```

In `--json` mode the plaintext lives inside the JSON, so it is not also written
to stdout (use `--out FILE` if you want it split into a file).

Set `PLAINCLOAK_ASCII=1` to render boxes and glyphs as plain ASCII, or
`PLAINCLOAK_FULL_HASH=1` to show full 64-char key hashes instead of the
abbreviated form.

Passwords are entered via a no-echo interactive prompt and are never accepted
as flag arguments. For scripts and CI, pipe the passphrase with
`--password-stdin` to avoid it appearing in shell history:

```sh
echo "$KEYSTORE_PASS" | plaincloak keygen --label alice --password-stdin
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | success / `verified` |
| 1 | generic CLI error |
| 2 | `unknown-sender` (plaintext produced) |
| 3 | `signature-invalid` (plaintext produced) |
| 4 | `wrong-recipient` (no plaintext) |
| 5 | `decryption-failed` (no plaintext) |
| 6 | malformed wire |
| 7 | plaintext too large / invalid key (producer side) |
| 8 | keystore locked or malformed |
| 9 | QR transport error (too large, missing `[qr]` extra, or undecodable) |

## Conformance

This implementation passes every vector in the pinned spec snapshot. See
[CONFORMANCE.md](CONFORMANCE.md) for the supported tier and the exact spec
commit.

## License

Apache-2.0. See [LICENSE](LICENSE).
