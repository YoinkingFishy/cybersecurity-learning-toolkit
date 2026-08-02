"""Tests for the hash manifest system (fully offline)."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest

from file_integrity.checker import check_manifest
from file_integrity.manifest import (
    create_manifest,
    load_manifest,
    save_manifest,
)

_DATA_A = b"manifest content A"
_DATA_B = b"manifest content B"


def _write_file(td: str, name: str, data: bytes) -> str:
    path = os.path.join(td, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


class ManifestCreationTests(unittest.TestCase):
    def test_create_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            a = _write_file(td, "a.txt", _DATA_A)
            b = _write_file(td, "b.txt", _DATA_B)
            manifest = create_manifest([a, b])
            self.assertEqual(manifest["algorithm"], "sha256")
            self.assertEqual(set(manifest["files"]), {"a.txt", "b.txt"})
            self.assertEqual(
                manifest["files"]["a.txt"], hashlib.sha256(_DATA_A).hexdigest()
            )

    def test_create_manifest_with_base_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            a = _write_file(td, "a.txt", _DATA_A)
            manifest = create_manifest([a], base_dir=td)
            self.assertEqual(manifest["files"]["a.txt"], hashlib.sha256(_DATA_A).hexdigest())

    def test_create_manifest_with_md5(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            a = _write_file(td, "a.txt", _DATA_A)
            manifest = create_manifest([a], algorithm="md5")
            self.assertEqual(manifest["algorithm"], "md5")
            self.assertEqual(
                manifest["files"]["a.txt"], hashlib.md5(_DATA_A).hexdigest()
            )

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            create_manifest(["does-not-exist.txt"])

    def test_unsupported_algorithm_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            a = _write_file(td, "a.txt", _DATA_A)
            with self.assertRaises(ValueError):
                create_manifest([a], algorithm="sha1")


class ManifestStorageTests(unittest.TestCase):
    def test_save_and_load_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            a = _write_file(td, "a.txt", _DATA_A)
            manifest = create_manifest([a])
            manifest_path = os.path.join(td, "manifest.json")
            save_manifest(manifest, manifest_path)
            loaded = load_manifest(manifest_path)
            self.assertEqual(loaded, manifest)

    def test_load_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_manifest("does-not-exist.json")

    def test_load_invalid_json_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            with self.assertRaises(ValueError):
                load_manifest(path)

    def test_load_unsupported_algorithm_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"algorithm": "sha1", "files": {}}')
            with self.assertRaises(ValueError):
                load_manifest(path)

    def test_load_invalid_digest_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"algorithm": "sha256", "files": {"a.txt": "zz"}}')
            with self.assertRaises(ValueError):
                load_manifest(path)

    def test_load_missing_files_field_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"algorithm": "sha256"}')
            with self.assertRaises(ValueError):
                load_manifest(path)


class ManifestCheckTests(unittest.TestCase):
    def test_check_manifest_all_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            a = _write_file(td, "a.txt", _DATA_A)
            manifest = create_manifest([a])
            results = check_manifest(manifest, base_dir=td)
            self.assertEqual(results[0]["status"], "unchanged")

    def test_check_manifest_detects_modified_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            a = _write_file(td, "a.txt", _DATA_A)
            manifest = create_manifest([a])
            with open(a, "ab") as handle:
                handle.write(b"tampered")
            results = check_manifest(manifest, base_dir=td)
            self.assertEqual(results[0]["status"], "modified")

    def test_check_manifest_detects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            a = _write_file(td, "a.txt", _DATA_A)
            manifest = create_manifest([a])
            os.remove(a)
            results = check_manifest(manifest, base_dir=td)
            self.assertEqual(results[0]["status"], "missing")


if __name__ == "__main__":
    unittest.main()
