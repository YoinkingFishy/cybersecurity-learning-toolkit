"""File hashing utilities built on :mod:`hashlib`."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union

SUPPORTED_ALGORITHMS = ("sha256", "md5")

_CHUNK_SIZE = 8192


def calculate_hash(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
    """Compute the hash of a file without loading it fully into memory.

    Args:
        file_path: Path to the file to hash.
        algorithm: ``"sha256"`` (recommended) or ``"md5"`` (compatibility).

    Returns:
        The lowercase hexadecimal digest of the file.

    Raises:
        ValueError: If ``algorithm`` is not supported.
        FileNotFoundError: If the file does not exist.
        IsADirectoryError: If the path is a directory.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"unsupported algorithm {algorithm!r}; expected one of "
            f"{SUPPORTED_ALGORITHMS}"
        )
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"file not found: {file_path}")
    if path.is_dir():
        raise IsADirectoryError(f"expected a file, got a directory: {file_path}")

    hasher = hashlib.new(algorithm)
    with open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()
