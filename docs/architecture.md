# Architecture

This document explains how the Cybersecurity Learning Toolkit is organized
and how its components interact.

## Layered design

```
                    ┌──────────────────────────┐
                    │       CLI (argparse)      │
                    │  port_scanner/cli.py      │
                    │  log_analyzer/cli.py      │
                    │  file_integrity/cli.py    │
                    └─────────────┬────────────┘
                                  │
              ┌───────────────────┼────────────────────┐
              │                   │                    │
   ┌──────────▼─────────┐ ┌──────▼────────┐ ┌─────────▼────────┐
   │  port_scanner      │ │ log_analyzer  │ │ file_integrity   │
   │  ─ scanner.py      │ │ ─ parsers.py  │ │ ─ hasher.py      │
   │  ─ validators.py   │ │ ─ detectors.py│ │ ─ manifest.py    │
   │  ─ exporters.py    │ │ ─ analyzer.py │ │ ─ checker.py     │
   │                    │ │ ─ exporters.py│ │                  │
   └────────────────────┘ └───────────────┘ └──────────────────┘
              │                    │                    │
       Standard library only: socket, argparse, csv, json,
       hashlib, pathlib, datetime, re, ipaddress, logging, collections
```

## Module responsibilities

### port_scanner

| Module       | Responsibility                                              |
| ------------ | ----------------------------------------------------------- |
| `scanner.py` | `PortScanner` class: TCP connect scanning with timeout.     |
| `validators.py` | Target/hostname, port, and range validation.             |
| `exporters.py` | Write results to TXT or CSV (never overwrite silently).  |
| `cli.py`     | Argument parsing, authorization warning, orchestration.     |

### log_analyzer

| Module         | Responsibility                                            |
| -------------- | --------------------------------------------------------- |
| `parsers.py`   | Line → structured event dicts (Apache, auth, Windows CSV).|
| `detectors.py` | Burst detection, unusual-IP heuristics, summaries.        |
| `analyzer.py`  | Pipeline: parse → detect → build report.                  |
| `exporters.py` | Report → TXT / CSV / JSON.                                |
| `cli.py`       | Format auto-detection, orchestration, summary printing.   |

### file_integrity

| Module         | Responsibility                                            |
| -------------- | --------------------------------------------------------- |
| `hasher.py`    | Chunked SHA-256 / MD5 hashing.                            |
| `manifest.py`  | Create, save, and *validate* JSON manifests.              |
| `checker.py`   | Per-file verification and full-manifest reports.          |
| `cli.py`       | `hash` / `create-manifest` / `check-manifest` commands.   |

### Shared conventions

- Every public function has type hints and a docstring.
- Parsers return `None` for unparseable input instead of raising.
- Exporters refuse to overwrite existing files (`FileExistsError`).
- No module performs network I/O except `port_scanner`, and only against the
  target supplied by the operator.
- Tests run entirely offline.

## Data flow examples

**Port scan:** `cli.py` validates inputs → `PortScanner.scan_range()` →
per-port `scan_port()` → result list → printed and/or exported.

**Log analysis:** `cli.py` → `analyze_log()` → `_parse_events()` →
`detectors` produce alerts and summary → report dict → printed/exported.

**Integrity check:** `cli.py check-manifest` → `load_manifest()` (validates
structure and digest format) → `check_manifest()` → per-file results.
