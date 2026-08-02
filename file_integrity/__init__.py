"""File Integrity Checker — hash generation and manifest verification."""

from .checker import check_file_integrity, check_manifest
from .hasher import calculate_hash

__all__ = ["calculate_hash", "check_file_integrity", "check_manifest"]
__version__ = "1.0.0"
