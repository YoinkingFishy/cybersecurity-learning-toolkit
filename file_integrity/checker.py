"""File integrity checking against known-good hashes and manifests."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Union

from .hasher import SUPPORTED_ALGORITHMS, calculate_hash

logger = logging.getLogger(__name__)


def check_file_integrity(
    file_path: Union[str, Path], expected_hash: str, algorithm: str = "sha256"
) -> Dict[str, str]:
    """Verify one file against an expected hash.

    Args:
        file_path: File to check.
        expected_hash: The known-good digest to compare against.
        algorithm: Hash algorithm used for ``expected_hash``.

    Returns:
        A dict with ``file``, ``expected_hash``, ``actual_hash``, and
        ``status`` keys. Status is ``"unchanged"``, ``"modified"``,
        ``"missing"``, or ``"error"``.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        return {
            "file": str(file_path),
            "expected_hash": expected_hash,
            "actual_hash": "",
            "status": "error",
        }
    path = Path(file_path)
    if not path.exists():
        return {
            "file": str(path),
            "expected_hash": expected_hash,
            "actual_hash": "",
            "status": "missing",
        }
    try:
        actual = calculate_hash(path, algorithm)
    except (OSError, IsADirectoryError) as exc:
        logger.warning("could not hash %s: %s", path, exc)
        return {
            "file": str(path),
            "expected_hash": expected_hash,
            "actual_hash": "",
            "status": "error",
        }
    status = "unchanged" if actual == expected_hash else "modified"
    return {
        "file": str(path),
        "expected_hash": expected_hash,
        "actual_hash": actual,
        "status": status,
    }


def check_manifest(
    manifest: Dict[str, object],
    base_dir: Union[str, Path, None] = None,
) -> List[Dict[str, str]]:
    """Check every file listed in a manifest.

    Args:
        manifest: A validated manifest from :func:`load_manifest`.
        base_dir: Directory that manifest entries are resolved relative to.
            When omitted, entries are resolved against the current working
            directory.

    Returns:
        A list of per-file check results (see :func:`check_file_integrity`).
    """
    algorithm = manifest["algorithm"]  # type: ignore[assignment]
    base = Path(base_dir).resolve() if base_dir is not None else Path.cwd()
    results: List[Dict[str, str]] = []
    for name, digest in manifest["files"].items():  # type: ignore[union-attr]
        results.append(check_file_integrity(base / name, digest, algorithm))
    return results
