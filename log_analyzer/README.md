# Log Analyzer

A defensive log analysis tool for locally supplied log files.

## What it does

Parses log files, summarizes activity, and flags potentially suspicious
patterns — **without ever labeling anything as definitively malicious**.

Supported formats:

- **Apache-style access logs** (combined log format)
- **Authentication logs** (syslog/sshd style: `Failed password for ... from <ip>`)
- **Windows event log exports** (CSV — column names are matched by alias)

## Why it exists

To teach log parsing, correlation, and anomaly detection from a defender's
perspective: recognizing failed-login bursts, probing, and unusual traffic
patterns in data you already own.

## How it works

1. `parsers.py` converts each log line into a structured event dict.
2. `detectors.py` groups events by IP and applies heuristic thresholds:
   - `detect_failed_login_bursts()` — N failures from one IP in a time window
   - `detect_unusual_ip_activity()` — frequency, 4xx spikes, suspicious paths
   - `summarize_ip_activity()` — overall stats
3. `analyzer.py` builds a report with recommended defensive actions.
4. `exporters.py` writes the report as TXT, CSV, or JSON.

## Installation

From the repository root:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
```

No third-party dependencies are required.

## Usage

```bash
# Analyze an Apache-style access log
python -m log_analyzer.cli --file examples/sample_apache.log --format apache

# Analyze an authentication log (format is auto-detected as apache if omitted)
python -m log_analyzer.cli --file examples/sample_system.log --format auth

# Analyze an exported Windows event log (CSV)
python -m log_analyzer.cli --file windows_export.csv --format windows-csv

# Save a JSON report
python -m log_analyzer.cli --file examples/sample_apache.log --output report.json

# Tune the burst detector
python -m log_analyzer.cli --file examples/sample_system.log --format auth --threshold 3 --window 5
```

### Output example

```text
Analyzed examples/sample_system.log (auth)
  Total events : 12
  Unique IPs   : 3
  Failed login : 1 burst alert(s)
  Unusual IPs  : 1 finding(s)
Report saved to: report.json
```

## Limitations

- Analysis quality depends on log completeness; missing timestamps disable
  true time-window detection (fallback: per-IP totals).
- Heuristic thresholds are configurable but not a substitute for a real
  SIEM or SOC workflow.
- The tool analyzes only files you point it at — it never connects anywhere.

## Security considerations

- Only analyze logs you are authorized to inspect.
- Reports may contain IP addresses — treat them as sensitive data.

## Authorized-use disclaimer

This tool is for educational and authorized defensive use only.
