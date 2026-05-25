# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in this library - a bug in the Python implementation that could compromise confidentiality, integrity, or authentication for a correct user - please report it privately. **Do not open a public issue.**

Send an email to: **PlainCloak@outlook.com** with the subject line beginning `[plaincloak-security]`.

## Scope

In-scope reports (implementation bugs in this library):

- A bug that causes `decrypt` to return `VERIFIED` when the signature is invalid.
- A bug that leaks plaintext when the outcome should be `WRONG_RECIPIENT` or `DECRYPTION_FAILED`.
- A timing or side-channel issue in a cryptographic operation.
- A keystore flaw that allows key material to be recovered without the passphrase.
- A decompression bug that bypasses the 1 MiB budget and enables a denial-of-service.

Out-of-scope (protocol-level flaws in the spec itself): please report to [plaincloak-spec](https://github.com/PlainCloak/plaincloak-spec) instead.

## What we will do

- Acknowledge your report within 72 hours.
- Investigate and confirm or refute the issue.
- Develop a fix and release a patched version.
- Credit you in `CHANGELOG.md` unless you prefer to remain anonymous.
