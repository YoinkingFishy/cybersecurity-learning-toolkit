"""Hash manifest creation, saving, and loading."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Union

from .hasher import SUPPORTED_ALGORITHMS, calculate_hash

_HEX_RE = frozenset("0123456789abcdef")


def create_manifest(
    file_paths: List[Union[str, Path]],
    algorithm: str = "sha256",
    base_dir: Union[str, Path, None] = None,
) -> Dict[str, object]:
    """Create a hash manifest for the given files.

    Args:
        file_paths: Files to include in the manifest.
        algorithm: Hash algorithm to use.
        base_dir: Directory that manifest entries are made relative to. When
            omitted, each file is stored by its basename.

    Returns:
        A manifest dict: ``{"algorithm": ..., "files": {name: hash}}``.

    Raises:
        ValueError: If ``algorithm`` is unsupported.
        FileNotFoundError: If any input file is missing.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"unsupported algorithm {algorithm!r}; expected one of {SUPPORTED_ALGORITHMS}"
        )
    base = Path(base_dir).resolve() if base_dir is not None else None
    files: Dict[str, str] = {}
    for path in file_paths:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"file not found: {path}")
        name = p.name if base is None else os.path.relpath(p.resolve(), base)
        files[name] = calculate_hash(p, algorithm)
    return {"algorithm": algorithm, "files": files}


def save_manifest(manifest: Dict[str, object], output_file: str) -> str:
    """Save a manifest to disk as JSON.

    Args:
        manifest: Manifest dict produced by :func:`create_manifest`.
        output_file: Destination path.

    Returns:
        The path of the written file.
    """
    path = Path(output_file)
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return str(path)


def load_manifest(manifest_file: str) -> Dict[str, object]:
    """Load and validate a hash manifest from disk.

    The manifest must be a JSON object with an ``algorithm`` field (one of the
    supported algorithms) and a ``files`` object mapping names to hex digests.
    Malformed manifests are rejected.

    Args:
        manifest_file: Path to the manifest JSON file.

    Returns:
        The validated manifest dict.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the manifest is malformed or uses an unsupported
            algorithm or digest format.
    """
    path = Path(manifest_file)
    if not path.is_file():
        raise FileNotFoundError(f"manifest file not found: {manifest_file}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError("manifest must be a JSON object")
    algorithm = raw.get("algorithm")
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"manifest uses unsupported algorithm {algorithm!r}")
    files = raw.get("files")
    if not isinstance(files, dict):
        raise ValueError("manifest 'files' must be an object mapping names to hashes")

    validated: Dict[str, str] = {}
    for name, digest in files.items():
        if not isinstance(name, str) or not isinstance(digest, str):
            raise ValueError(f"manifest entry {name!r} is malformed")
        expected_len = 64 if algorithm == "sha256" else 32
        if len(digest) != expected_len or any(c not in _HEX_RE for c in digest):
            raise ValueError(f"manifest entry {name!r} has an invalid digest")
        validated[name] = digest
    return {"algorithm": algorithm, "files": validated}
