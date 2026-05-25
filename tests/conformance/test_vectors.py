from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from .runner import dispatch

VECTORS_ROOT = Path(__file__).resolve().parent.parent / "vectors" / "v1"


def _collect() -> list[tuple[str, str, str, dict[str, Any], dict[str, Any]]]:
    """Walk the vendored vectors and yield (file, category, id, in, expected) tuples."""
    out: list[tuple[str, str, str, dict[str, Any], dict[str, Any]]] = []
    for path in sorted(VECTORS_ROOT.rglob("*.json")):
        # Skip the top-level schema and fixtures.
        if path.parent.name in {"fixtures", "keys"} or path.name == "schema.json":
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        category = doc.get("category")
        cases = doc.get("cases")
        if not category or not isinstance(cases, list):
            continue
        for case in cases:
            out.append(
                (
                    str(path.relative_to(VECTORS_ROOT)),
                    category,
                    case.get("id", "<no-id>"),
                    case.get("inputs", {}),
                    case.get("expected", {}),
                )
            )
    return out


_CASES = _collect()


@pytest.mark.parametrize(
    ("file", "category", "case_id", "inputs", "expected"),
    _CASES,
    ids=[f"{c[1]}:{c[2]}" for c in _CASES],
)
def test_conformance_vector(
    file: str,
    category: str,
    case_id: str,
    inputs: dict[str, Any],
    expected: dict[str, Any],
) -> None:
    """Run a single vendored conformance case."""
    dispatch(category, inputs, expected)
