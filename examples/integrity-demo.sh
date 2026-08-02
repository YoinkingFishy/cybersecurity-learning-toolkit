#!/usr/bin/env bash
# Demonstrate the file integrity checker end to end.
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

echo '== create baseline =='
python -m file_integrity.cli create-manifest examples/*.log --output /tmp/demo-manifest.json

echo '== verify unchanged =='
python -m file_integrity.cli check-manifest /tmp/demo-manifest.json

echo '== tamper with a file =='
printf '\ntampered' >> examples/sample_mixed.log

echo '== verify again (expect modified) =='
python -m file_integrity.cli check-manifest /tmp/demo-manifest.json || true

echo '== restore =='
git checkout examples/sample_mixed.log
rm -f /tmp/demo-manifest.json
echo done