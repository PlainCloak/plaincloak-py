from __future__ import annotations

from plaincloak.core.suites.base import Suite
from plaincloak.core.suites.rsa_oaep_aes256gcm_sha256 import (
    RsaOaepAes256GcmSha256Suite,
)
from plaincloak.core.suites.rsa_oaep_sha256 import RsaOaepSha256Suite
from plaincloak.exceptions import UnknownSuiteError

SUITES: dict[str, Suite] = {
    "RSA-OAEP-SHA256": RsaOaepSha256Suite(),
    "RSA-OAEP-AES256GCM-SHA256": RsaOaepAes256GcmSha256Suite(),
}


def get_suite(identifier: str) -> Suite:
    """Return the suite registered for `identifier`.

    Args:
        identifier (str): Body `a` field value.

    Raises:
        UnknownSuiteError: If no suite is registered for `identifier`.

    Returns:
        Suite: The suite implementation.
    """
    try:
        return SUITES[identifier]
    except KeyError as exc:
        raise UnknownSuiteError(
            f"suite {identifier!r} is not in this implementation's registry"
        ) from exc
