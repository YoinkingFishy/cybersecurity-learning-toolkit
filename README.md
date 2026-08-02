# Cybersecurity Learning Toolkit

![License](https://img.shields.io/github/license/YoinkingFishy/cybersecurity-learning-toolkit)
![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-unittest-blue)

> **IMPORTANT:** This repository is intended exclusively for educational purposes, defensive security research, CTF competitions, personal labs, and authorized security testing. Only use these tools against systems that you own or have explicit permission to test. The authors are not responsible for misuse, unauthorized access, damage, or illegal activity resulting from the use of this repository.

## Overview

A beginner-to-intermediate Python cybersecurity learning toolkit. It contains four
small, focused, well-tested projects that teach core security concepts while
following defensive, educational, and authorized-use principles:

1. **Python Port Scanner** — a TCP connect scanner built on the standard `socket` library.
2. **Log Analyzer** — a defensive log parsing and anomaly detection tool.
3. **File Integrity Checker** — hash generation and manifest-based integrity verification.
4. **CTF Write-up Repository** — structured Markdown templates for documenting CTF challenges.

Every tool uses only Python's standard library. No third-party dependencies are
required at runtime.

## Projects

### 1. Python Port Scanner

A TCP connect scanner for localhost, private labs, CTF environments, and systems
you are authorized to test. It reports ports as `open`, `closed`, `filtered`, or
`error`, and exports results to text or CSV.

```bash
python -m port_scanner.cli --target 127.0.0.1 --ports 22,80,443
python -m port_scanner.cli --target 127.0.0.1 --start-port 1 --end-port 100 --output results.csv --format csv
```

### 2. Log Analyzer

A defensive tool that parses Apache-style access logs, generic authentication
logs, and exported Windows event logs (CSV). It flags failed-login bursts and
unusual IP activity, then produces a report with recommended defensive actions.

```bash
python -m log_analyzer.cli --file examples/sample_apache.log --format apache
python -m log_analyzer.cli --file examples/sample_system.log --format auth --output report.json
```

### 3. File Integrity Checker

Computes SHA-256 (or MD5) hashes of files, creates JSON hash manifests, and
verifies files against a trusted baseline.

```bash
python -m file_integrity.cli hash example.txt
python -m file_integrity.cli create-manifest file1.txt file2.txt --output manifest.json
python -m file_integrity.cli check-manifest manifest.json
```

### 4. CTF Write-ups

A Markdown-based knowledge repository organized by platform (TryHackMe, PicoCTF),
with a fixed write-up structure that always includes lessons learned and
defensive remediation sections.

## Features

- 100% Python standard library (no runtime dependencies)
- Type hints, docstrings, and PEP 8 throughout
- Comprehensive offline test suite (`unittest`, no internet required)
- Structured, reproducible CLI interfaces
- Clear authorization warnings and ethical guidance in every tool
- No offensive, stealth, or evasion functionality

## Requirements

- Python 3.9 or newer
- No third-party packages required at runtime
- `pytest` (optional) for running tests with a nicer runner — see `requirements-dev.txt`

## Installation

```bash
git clone <YOUR_REPOSITORY_URL>
cd cybersecurity-learning-toolkit

python -m venv .venv
```

Activate the virtual environment:

Windows (PowerShell):

```powershell
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies (none are required at runtime; `requirements-dev.txt` is
only for development):

```bash
pip install -r requirements-dev.txt   # optional, for pytest
```

## Usage

Each project has its own README with full command reference and examples:

- `port_scanner/README.md`
- `log_analyzer/README.md`
- `file_integrity/README.md`
- `ctf_writeups/README.md`

Quick examples:

```bash
# Scan a small set of ports on localhost
python -m port_scanner.cli --target 127.0.0.1 --ports 22,80,443

# Analyze an Apache access log
python -m log_analyzer.cli --file examples/sample_apache.log --format apache

# Create and verify a hash manifest
python -m file_integrity.cli create-manifest examples/sample_apache.log
python -m file_integrity.cli check-manifest manifest.json
```

## Project Structure

```text
cybersecurity-learning-toolkit/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── .gitignore
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── port_scanner/
├── log_analyzer/
├── file_integrity/
├── ctf_writeups/
├── tests/
├── examples/
└── docs/
```

## Security Disclaimer

**IMPORTANT:** This repository is intended exclusively for educational purposes,
defensive security research, CTF competitions, personal labs, and authorized
security testing.

Only use these tools against systems that you own or have explicit permission
to test.

The authors are not responsible for misuse, unauthorized access, damage, or
illegal activity resulting from the use of this repository.

## Authorized Use

You may use this toolkit only when at least one of the following is true:

- The target system is your own.
- You have written, explicit permission from the system owner.
- The activity takes place inside an authorized lab or CTF environment.

Scanning or probing systems without authorization may be illegal in many
jurisdictions. You are responsible for knowing and following the laws that
apply to you.

## Ethical Guidelines

- Always verify authorization before running any tool.
- Keep test activity inside lab environments.
- Never use these tools to access data you are not permitted to see.
- Report vulnerabilities you discover responsibly, never publicly first.
- Use the CTF write-ups to teach others — do not publish other people's
  copyrighted solutions verbatim.

## Testing

The test suite uses only the standard library and never touches the internet.

```bash
python -m unittest discover -s tests -v
```

Or with pytest:

```bash
pytest tests -v
```

## Contributing

Please read `CONTRIBUTING.md` before opening a pull request.

## License

MIT — see `LICENSE`.
