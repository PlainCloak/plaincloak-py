from __future__ import annotations


def build_canonical(
    *,
    wire_version_int: int,
    a: str,
    i: str,
    t: int,
    s: str,
    r: str,
    p: str,
) -> bytes:
    """Return the canonical-form bytes for signature input.

    Args:
        wire_version_int (int): Integer obtained from the envelope's version
            token (e.g. `1` for `v1`).
        a (str): Body suite identifier (`a` field).
        i (str): Body message identifier (`i` field, UUIDv4 lowercase).
        t (int): Body timestamp in Unix milliseconds (`t` field).
        s (str): Body sender public-key hash (`s` field, 64 lowercase hex).
        r (str): Body recipient public-key hash (`r` field, 64 lowercase hex).
        p (str): Body encrypted payload (`p` field, Base64 string).

    Returns:
        bytes: UTF-8 encoded canonical-form string per spec section 7.2.
    """
    return (
        f"{wire_version_int}:{a}:{i}:{t}:{s}:{r}:{p}"
    ).encode()


def build_aad(
    *,
    wire_version_int: int,
    a: str,
    i: str,
    t: int,
    s: str,
    r: str,
) -> bytes:
    """Return the AAD bytes for the hybrid AEAD suite.

    The AAD is the canonical form with the `p` segment empty (the trailing
    colon is preserved). The hybrid suite encrypts the plaintext, so the
    `p`-derived ciphertext cannot itself be part of the AAD.

    Args:
        wire_version_int (int): Integer from the envelope's version token.
        a (str): Body suite identifier.
        i (str): Body message identifier.
        t (int): Body timestamp.
        s (str): Body sender public-key hash.
        r (str): Body recipient public-key hash.

    Returns:
        bytes: UTF-8 encoded canonical form with an empty `p` segment.
    """
    return build_canonical(
        wire_version_int=wire_version_int,
        a=a,
        i=i,
        t=t,
        s=s,
        r=r,
        p="",
    )
