# File Integrity Checker

A file hashing and integrity verification tool.

## What it does

- Computes **SHA-256** or **MD5** hashes of local files.
- Creates a **JSON hash manifest** (a trusted baseline of known-good digests).
- Checks files against a manifest and reports each file as `unchanged`,
  `modified`, `missing`, or `error`.

## Why it exists

To teach how cryptographic hashes detect file tampering and drift, and to
demonstrate why a **trusted baseline** and a **strong algorithm** matter.

## How it works

1. `hasher.py` reads files in 8 KB chunks and feeds them to `hashlib` — the
   file is never loaded fully into memory.
2. `manifest.py` creates, saves, and validates JSON manifests.
3. `checker.py` compares current digests against the manifest and classifies
   each file's state.

## Installation

From the repository root:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
```

No third-party dependencies are required.

## Usage

```bash
# Hash a single file
python -m file_integrity.cli hash example.txt
# -> sha256: <digest>  example.txt

# Hash with MD5 (compatibility only)
python -m file_integrity.cli hash example.txt --algorithm md5

# Create a baseline manifest
python -m file_integrity.cli create-manifest file1.txt file2.txt --output manifest.json

# Verify files against the baseline
python -m file_integrity.cli check-manifest manifest.json
```

### Output example (check-manifest)

```text
  UNCHANGED  file1.txt
  MODIFIED   file2.txt  (expected <digest>)

1/2 files unchanged
```

## Limitations

- A hash proves a file *changed*, not *who* changed it.
- Hashing cannot detect intentional tampering if the attacker also updates
  the manifest — the baseline must be stored somewhere trusted.
- MD5 is cryptographically weak (collisions) and is provided only for
  compatibility and education.

## Security considerations

- Always use **SHA-256** for integrity checking.
- Store the baseline manifest securely (read-only media, offline backup, or
  a signing system).
- Recompute the baseline only after a verified, authorized change.

## Authorized-use disclaimer

This tool is for educational purposes and authorized defensive use only.
