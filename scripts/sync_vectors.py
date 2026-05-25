from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

SPEC_REF = "4e33e7387836948bc8c449d97d1eefd89bcd8899"
SPEC_REPO = "PlainCloak/plaincloak-spec"
TARBALL_URL = f"https://github.com/{SPEC_REPO}/archive/{SPEC_REF}.tar.gz"
TARBALL_PREFIX = f"plaincloak-spec-{SPEC_REF}"

REPO_ROOT = Path(__file__).resolve().parents[1]

SCHEMA_FILES = (
    "message.schema.json",
    "keystore.schema.json",
    "algorithms.json",
    "compression.json",
)

SCHEMA_DST = REPO_ROOT / "src" / "plaincloak" / "core" / "schemas"
VECTORS_DST = REPO_ROOT / "tests" / "vectors" / "v1"


def _download_spec(dest: Path) -> Path:
    """Download the spec tarball and extract it into dest.

    Args:
        dest (Path): Directory to extract into.

    Returns:
        Path: Root of the extracted spec tree (the inner plaincloak-spec-* dir).
    """
    tarball = dest / "spec.tar.gz"
    print(f"Downloading {TARBALL_URL}")
    urllib.request.urlretrieve(TARBALL_URL, tarball)  # noqa: S310
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(dest, filter="data")
    return dest / TARBALL_PREFIX


def _copy_schemas(spec_root: Path, dst: Path) -> None:
    """Copy the four vendored schema/registry files from spec_root into dst."""
    src = spec_root / "schemas" / "v1"
    dst.mkdir(parents=True, exist_ok=True)
    for name in SCHEMA_FILES:
        f = src / name
        if not f.is_file():
            raise FileNotFoundError(f"Missing spec schema file: {f}")
        shutil.copy2(f, dst / name)


def _copy_vectors(spec_root: Path, dst: Path) -> None:
    """Mirror the spec's v1 test-vectors tree into dst."""
    src = spec_root / "test-vectors" / "v1"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def _trees_equal(a: Path, b: Path) -> bool:
    """Recursive byte-exact compare of two directory trees.

    Returns:
        bool: True only if every file under a exists identically under b
            and vice versa.
    """
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    for subdir in cmp.common_dirs:
        if not _trees_equal(a / subdir, b / subdir):
            return False
    return True


def sync(check_only: bool) -> int:
    """Download the spec snapshot and sync vendored files, or check for drift.

    Args:
        check_only (bool): If True, compare a fresh download against the
            vendored copy without modifying anything. Returns 1 on drift.

    Returns:
        int: 0 on success or no drift; 1 on detected drift (check mode only).
    """
    with tempfile.TemporaryDirectory() as tmp:
        spec_root = _download_spec(Path(tmp))

        if not check_only:
            print(f"Syncing schemas -> {SCHEMA_DST}")
            _copy_schemas(spec_root, SCHEMA_DST)
            print(f"Syncing vectors -> {VECTORS_DST}")
            _copy_vectors(spec_root, VECTORS_DST)
            print("Sync complete.")
            return 0

        fresh_schemas = Path(tmp) / "fresh_schemas"
        fresh_vectors = Path(tmp) / "fresh_vectors"
        _copy_schemas(spec_root, fresh_schemas)
        _copy_vectors(spec_root, fresh_vectors)

        schemas_ok = SCHEMA_DST.is_dir() and _trees_equal(fresh_schemas, SCHEMA_DST)
        vectors_ok = VECTORS_DST.is_dir() and _trees_equal(fresh_vectors, VECTORS_DST)

        if schemas_ok and vectors_ok:
            print("No drift; vendored snapshot matches spec.")
            return 0

        if not schemas_ok:
            print(f"Schema drift: {SCHEMA_DST} differs from spec.", file=sys.stderr)
        if not vectors_ok:
            print(f"Vector drift: {VECTORS_DST} differs from spec.", file=sys.stderr)
        print("Run `python scripts/sync_vectors.py` to refresh.", file=sys.stderr)
        return 1


def main() -> int:
    """CLI entry: parse args and dispatch to sync."""
    parser = argparse.ArgumentParser(
        description="Sync vendored schemas and test vectors from the public "
                    "spec repo.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare without modifying; exit 1 on drift.",
    )
    return sync(check_only=parser.parse_args().check)


if __name__ == "__main__":
    sys.exit(main())
