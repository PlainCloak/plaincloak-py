# Changelog

All notable changes to `plaincloak-py` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[1.0.0]: https://github.com/PlainCloak/plaincloak-py/releases/tag/v1.0.0
