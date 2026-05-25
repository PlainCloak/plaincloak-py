# Conformance

## Supported tier

`plaincloak-py` implements the **PlainCloak v1 core profile** in full:

- Wire format and strict parser (spec sections 3, 4).
- Brotli compression with a streaming 1 MiB decompression budget (section 5).
- Message body and `message.schema.json` validation (section 6).
- Canonical form for signing and the hybrid AAD (section 7).
- Both registered v1 suites (section 8):
  - `RSA-OAEP-SHA256` (REQUIRED baseline)
  - `RSA-OAEP-AES256GCM-SHA256` (RECOMMENDED hybrid)
- Key identification via SPKI-DER SHA-256 (section 9).
- Producer and consumer procedures, including all five section 10.3 outcomes.

RSA modulus sizes 2048, 3072, and 4096 are supported; the public exponent is
fixed at 65537. Reserved compression code `ZS` and any unknown suite are
rejected per the open-registry rules.

## Pinned spec commit

The vendored schemas (`src/plaincloak/core/schemas/`) and test vectors
(`tests/vectors/v1/`) are a snapshot of `plaincloak-spec` at:

```
4e33e7387836948bc8c449d97d1eefd89bcd8899
```

`scripts/sync_vectors.py` reproduces the snapshot; `scripts/sync_vectors.py
--check` (run in CI) fails on any drift from this commit. The commit is
pinned as `SPEC_REF` in `scripts/sync_vectors.py`; update it there when
re-syncing.

## Vectors passed

Every JSON vector in the snapshot passes (`pytest tests/conformance/`):

**Deterministic (6 files):** `01-base62-encode`, `02-base62-decode`,
`03-brotli-roundtrip`, `04-canonical-form`, `05-key-hash-spki`,
`06-message-id-formatting`.

**Verification (12 files):** `01-rsa2048-roundtrip`, `02-rsa4096-roundtrip`,
`03-tampered-payload`, `04-tampered-signature`, `05-wrong-recipient`,
`06-unknown-sender`, `07-rsa2048-hybrid-roundtrip`,
`08-rsa4096-hybrid-roundtrip`, `09-hybrid-long-plaintext`,
`10-hybrid-tampered-wrap`, `11-hybrid-tampered-tag`,
`12-hybrid-signature-invalid`.

Brotli compressed bytes are not byte-stable across encoders; the
`brotli-roundtrip` vectors are checked by the round-trip property only, as
the spec requires.
