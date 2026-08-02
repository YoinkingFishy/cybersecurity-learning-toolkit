"""Tests for the File Hash Generator and Integrity Checker (fully offline)."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest

from file_integrity.checker import check_file_integrity
from file_integrity.hasher import calculate_hash

_DATA = b"hello world from the integrity checker"


def _write_file(td: str, name: str, data: bytes = _DATA) -> str:
    path = os.path.join(td, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


class HashGeneratorTests(unittest.TestCase):
    def test_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_file(td, "a.txt")
            expected = hashlib.sha256(_DATA).hexdigest()
            self.assertEqual(calculate_hash(path, "sha256"), expected)

    def test_md5(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_file(td, "a.txt")
            expected = hashlib.md5(_DATA).hexdigest()
            self.assertEqual(calculate_hash(path, "md5"), expected)

    def test_default_algorithm_is_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_file(td, "a.txt")
            self.assertEqual(calculate_hash(path), hashlib.sha256(_DATA).hexdigest())

    def test_unsupported_algorithm_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_file(td, "a.txt")
            with self.assertRaises(ValueError):
                calculate_hash(path, "sha1")

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            calculate_hash("does-not-exist.txt")


class IntegrityCheckerTests(unittest.TestCase):
    def _expected(self) -> str:
        return hashlib.sha256(_DATA).hexdigest()

    def test_unchanged_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_file(td, "a.txt")
            result = check_file_integrity(path, self._expected())
            self.assertEqual(result["status"], "unchanged")
            self.assertEqual(result["actual_hash"], self._expected())

    def test_modified_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_file(td, "a.txt")
            with open(path, "ab") as handle:
                handle.write(b"tampered")
            result = check_file_integrity(path, self._expected())
            self.assertEqual(result["status"], "modified")

    def test_missing_file(self) -> None:
        result = check_file_integrity("does-not-exist.txt", self._expected())
        self.assertEqual(result["status"], "missing")

    def test_unsupported_algorithm_reports_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = _write_file(td, "a.txt")
            result = check_file_integrity(path, self._expected(), algorithm="sha1")
            self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main()
