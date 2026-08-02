"""Command-line interface for the File Integrity Checker."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from .checker import check_manifest
from .hasher import SUPPORTED_ALGORITHMS, calculate_hash
from .manifest import create_manifest, load_manifest, save_manifest


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m file_integrity.cli",
        description="File hash generation and integrity checking.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    hash_parser = subparsers.add_parser("hash", help="Print the hash of a file")
    hash_parser.add_argument("file", help="File to hash")

    create_parser = subparsers.add_parser(
        "create-manifest", help="Create a hash manifest for one or more files"
    )
    create_parser.add_argument("files", nargs="+", help="Files to include in the manifest")
    create_parser.add_argument("--output", default="manifest.json", help="Output manifest file")
    create_parser.add_argument(
        "--base-dir",
        default=None,
        help="Directory that manifest entries are relative to (default: the "
        "output manifest's directory)",
    )

    check_parser = subparsers.add_parser(
        "check-manifest", help="Verify files against a manifest"
    )
    check_parser.add_argument("manifest", help="Manifest JSON file")

    parser.add_argument(
        "--algorithm",
        choices=list(SUPPORTED_ALGORITHMS),
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    return parser


def _print_algorithm_notes(algorithm: str) -> None:
    """Print honest guidance about the chosen algorithm."""
    if algorithm == "md5":
        print(
            "Note: MD5 is provided for compatibility and educational purposes "
            "only. Use SHA-256 for integrity checking."
        )
    print("Note: a hash alone does not prove who modified a file.")
    print("Note: always verify against a trusted, securely stored baseline.")


def _cmd_hash(args: argparse.Namespace) -> int:
    try:
        digest = calculate_hash(args.file, args.algorithm)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{args.algorithm}: {digest}  {args.file}")
    _print_algorithm_notes(args.algorithm)
    return 0


def _cmd_create_manifest(args: argparse.Namespace) -> int:
    try:
        base_dir = args.base_dir or str(Path(args.output).resolve().parent)
        manifest = create_manifest(args.files, args.algorithm, base_dir=base_dir)
        written = save_manifest(manifest, args.output)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Manifest saved to: {written} ({len(manifest['files'])} files)")
    _print_algorithm_notes(args.algorithm)
    return 0


def _cmd_check_manifest(args: argparse.Namespace) -> int:
    try:
        manifest = load_manifest(args.manifest)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    results = check_manifest(manifest, base_dir=Path(args.manifest).resolve().parent)
    unchanged = sum(1 for r in results if r["status"] == "unchanged")
    for result in results:
        print(
            f"  {result['status'].upper():<9} {result['file']}"
            + (f"  (expected {result['expected_hash']})" if result["status"] != "unchanged" else "")
        )
    print(f"\n{unchanged}/{len(results)} files unchanged")
    return 0 if unchanged == len(results) else 1


def main(argv: Optional[list] = None) -> int:
    """Run the file integrity CLI.

    Returns:
        Process exit code (0 on success, 1 on error or integrity failure).
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "hash":
        return _cmd_hash(args)
    if args.command == "create-manifest":
        return _cmd_create_manifest(args)
    if args.command == "check-manifest":
        return _cmd_check_manifest(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
