# Changelog

All notable changes to `plaincloak-py` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-07-05

### Added

- `decrypt` accepts an `allow_identity_compression` flag (default `False`):
  the diagnostic `NO` compression code is now refused in normal consumption
  per spec section 5.3.
- `parse_envelope` accepts `decompress_budget_bytes`, matching `decrypt`.
- `encrypt` and `decrypt` accept `max_body_bytes` (default 64 KiB, the spec
  section 6.5 practical limit) so deployments moving large payloads can
  raise the body cap on both ends. Exposed on the CLI as `--max-body-bytes`;
  `plaincloak decrypt` also gains `--decompress-budget`.

### Changed

- Wire parsing tolerates trailing whitespace per spec section 3.3 step 5;
  a pasted wire ending in a newline no longer needs caller-side trimming.
- `decrypt` rejects decompressed bodies larger than 64 KiB (spec
  section 6.5 practical limit).
- Vendored spec snapshot re-pinned to `0d56772` (editorial changes only;
  schemas and test vectors unchanged).
- Wire parsing checks fields in the spec section 3.3 step order, so the
  error category reflects the first failing step (e.g. a `v2` envelope
  with extra colons reports `unsupported-version`, not `malformed`).

### Fixed

- Consumer-side key validation (spec section 8.2): forbidden RSA keys
  (modulus below 2048 bits or public exponent other than 65537) are now
  rejected by the PEM loaders, and by `decrypt` for the keys a message
  actually matches (recipient private key via `r`, trusted sender via `s`).
  Previously only `encrypt` validated keys.

## [1.0.1] - 2026-07-04

### Fixed

- Decompression budget is now enforced at the output layer: each Brotli
  `process()` call is capped with `output_buffer_limit`, so a decompression
  bomb peaks near the 1 MiB budget instead of allocating its full
  decompressed size before rejection (spec section 5.4).

### Changed

- `brotli` dependency floor raised to 1.2 (first release with `output_buffer_limit`).

## [1.0.0] - 2026-05-25

Initial public release of the PlainCloak v1 Python reference implementation.

### Added

- Public API: `generate_keypair`, `load_public_key_pem`,
  `load_private_key_pem`, `key_hash`, `encrypt`, `decrypt`,
  `parse_envelope`, `encode_qr`, `decode_qr`; plus the `Suite`, `Outcome`,
  `KeyPair`, `EnvelopeInfo`, `DecryptResult` types and the `PlainCloakError`
  exception hierarchy.
- Both v1 suites: `RSA-OAEP-SHA256` (REQUIRED baseline) and
  `RSA-OAEP-AES256GCM-SHA256` (RECOMMENDED hybrid).
- Wire codecs: bijective Base62, strict envelope parser, streaming Brotli
  with a 1 MiB decompression budget, JSON body schema validation.
- Canonical-form construction with wire-version domain separation for
  signatures and the hybrid AAD.
- Key identification via SPKI-DER SHA-256.
- Encrypted at-rest keystore with Argon2id (via the `[keystore]` extra) and
  a stdlib PBKDF2-SHA256 fallback; AES-256-GCM or ChaCha20-Poly1305 AEAD.
- QR code encode/decode support via the `[qr]` extra.
- `plaincloak` CLI (and `python -m plaincloak`): `keygen`, `encrypt`,
  `decrypt`, `inspect`, `keystore`, and `qr` subcommands with a
  deterministic exit-code map.
- Vendored spec schemas and test vectors with a CI drift check; passes
  all deterministic and verification conformance vectors.

[1.1.0]: https://github.com/PlainCloak/plaincloak-py/releases/tag/v1.1.0
[1.0.1]: https://github.com/PlainCloak/plaincloak-py/releases/tag/v1.0.1
[1.0.0]: https://github.com/PlainCloak/plaincloak-py/releases/tag/v1.0.0
