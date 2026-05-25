from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from plaincloak.exceptions import InvalidBodyError, InvalidJSONError

_BODY_FIELD_ORDER: tuple[str, ...] = ("a", "i", "t", "s", "r", "p", "g")


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    """Return a cached `Draft202012Validator` for the message body schema.

    Returns:
        Draft202012Validator: Validator bound to the vendored
            `message.schema.json` shipped with the package.
    """
    schema_text = (
        files("plaincloak.core.schemas")
        .joinpath("message.schema.json")
        .read_text(encoding="utf-8")
    )
    schema = json.loads(schema_text)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def parse(raw: bytes) -> dict[str, Any]:
    """Decode UTF-8 JSON bytes into a body dictionary.

    Args:
        raw (bytes): Decompressed body bytes.

    Raises:
        InvalidJSONError: If `raw` is not valid UTF-8 or not valid JSON, or
            if the top-level JSON value is not an object.

    Returns:
        dict[str, Any]: Parsed JSON object.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidJSONError(f"body is not valid UTF-8: {exc}") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidJSONError(f"body is not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise InvalidJSONError("body JSON top-level value MUST be an object")
    return value


def validate(body: dict[str, Any]) -> None:
    """Validate a parsed body against `message.schema.json`.

    Args:
        body (dict[str, Any]): Parsed JSON body to validate.

    Raises:
        InvalidBodyError: If `body` does not satisfy the schema. The error
            message names the offending field path so callers can surface a
            useful diagnostic.
    """
    try:
        _validator().validate(body)
    except ValidationError as exc:
        path = ".".join(str(p) for p in exc.absolute_path) or "<root>"
        raise InvalidBodyError(
            f"body failed schema validation at {path}: {exc.message}"
        ) from exc


def serialize(body: dict[str, Any]) -> bytes:
    """Serialize a body dict to compact UTF-8 JSON bytes.

    Field order in the output follows `a, i, t, s, r, p, g` for readability
    of test fixtures; the wire protocol does not require any order.

    Args:
        body (dict[str, Any]): Body dictionary with the seven v1 fields.

    Returns:
        bytes: Compact JSON encoded as UTF-8.

    Raises:
        KeyError: If `body` is missing a required field. Callers that build
            bodies through the public API never hit this path; it surfaces
            programmer error early during construction.
    """
    ordered = {key: body[key] for key in _BODY_FIELD_ORDER}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
