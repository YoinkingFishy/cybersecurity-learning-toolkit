# Usage Guide

A quick reference for running every tool in the toolkit.

## Prerequisites

- Python 3.9+
- No third-party packages required

## Port Scanner

```bash
# Scan specific ports
python -m port_scanner.cli --target 127.0.0.1 --ports 22,80,443

# Scan a range on localhost
python -m port_scanner.cli --target 127.0.0.1 --start-port 1 --end-port 100

# Export to CSV
python -m port_scanner.cli --target 127.0.0.1 --ports 22,80,443 --output results.csv --format csv

# Adjust timeout
python -m port_scanner.cli --target 127.0.0.1 --ports 22 --timeout 0.5
```

## Log Analyzer

```bash
# Apache-style access log
python -m log_analyzer.cli --file examples/sample_apache.log --format apache

# Authentication log (syslog/sshd style)
python -m log_analyzer.cli --file examples/sample_system.log --format auth

# Exported Windows event log (CSV)
python -m log_analyzer.cli --file export.csv --format windows-csv

# Save report as JSON
python -m log_analyzer.cli --file examples/sample_apache.log --output report.json

# Tune burst detection
python -m log_analyzer.cli --file examples/sample_system.log --format auth --threshold 3 --window 5
```

Format auto-detection: if `--format` is omitted, `.csv` files are treated as
`windows-csv`; everything else defaults to `apache`.

## File Integrity Checker

```bash
# Hash a single file (SHA-256)
python -m file_integrity.cli hash notes.txt

# Hash with MD5 (compatibility only)
python -m file_integrity.cli hash notes.txt --algorithm md5

# Create a baseline manifest
python -m file_integrity.cli create-manifest notes.txt config.ini --output manifest.json

# Verify files against the baseline
python -m file_integrity.cli check-manifest manifest.json
```

Exit codes: `0` = all files unchanged; `1` = error or integrity failure.

## Running the test suite

```bash
python -m unittest discover -s tests -v
```

## Troubleshooting

| Symptom                          | Likely cause / fix                          |
| -------------------------------- | ------------------------------------------- |
| `FileExistsError` on export      | The output file exists — choose another name or delete it. |
| Port shows `filtered`            | Timeout — firewall/proxy may be dropping traffic. |
| Log lines skipped                | Line format didn't match the selected parser. |
| `check-manifest` says `missing`  | Files must be checked from the same directory they were added in. |
