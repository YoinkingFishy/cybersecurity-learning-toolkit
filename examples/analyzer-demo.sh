#!/usr/bin/env bash
# Demonstrate the log analyzer on every bundled sample.
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

python -m log_analyzer.cli --file examples/sample_apache.log --format apache
echo '---'
python -m log_analyzer.cli --file examples/sample_sshd.log --format auth
echo '---'
python -m log_analyzer.cli --file examples/sample_windows_events.csv
echo '---'
python -m log_analyzer.cli --file examples/sample_mixed.log --format apache
echo done