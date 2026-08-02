# Python Port Scanner

A simple, educational TCP connect scanner built on Python's standard `socket`
library.

## What it does

Attempts a TCP connection to each target port and reports the result:

- `open` — the port accepted a connection
- `closed` — the port refused the connection
- `filtered` — the connection timed out or the host was unreachable
- `error` — an unexpected error occurred

Results can be exported to a clean text report or a CSV file
(`target,port,status`).

## Why it exists

To teach the fundamentals of TCP connection scanning (three-way handshake,
`connect_ex`, socket timeouts) in a safe, defensive, and authorized context.
The scanner has **no** stealth, evasion, or packet-crafting features.

## How it works

1. `PortScanner.scan_port()` opens a socket and calls `connect_ex()` with a
   configurable timeout.
2. `scan_ports()` runs that check over a list of ports.
3. `scan_range()` validates and expands a start/end range.
4. `exporters.py` writes the results to TXT or CSV.

## Installation

From the repository root:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
```

No third-party dependencies are required.

## Usage

```bash
# Scan a small set of ports
python -m port_scanner.cli --target 127.0.0.1 --ports 22,80,443

# Scan a range (e.g. the first 100 ports on localhost)
python -m port_scanner.cli --target 127.0.0.1 --start-port 1 --end-port 100

# Save results to CSV
python -m port_scanner.cli --target 127.0.0.1 --ports 22,80,443 --output results.csv --format csv

# Save results to a text report
python -m port_scanner.cli --target 127.0.0.1 --ports 22,80,443 --output results.txt
```

### Output example (TXT)

```text
Cybersecurity Learning Toolkit
Port Scan Results
=============================

Target: 127.0.0.1

Port 22    OPEN
Port 80    CLOSED
Port 443   FILTERED
```

### Output example (CSV)

```csv
target,port,status
127.0.0.1,22,open
127.0.0.1,80,closed
```

## Limitations

- TCP connect scanning only — no UDP, SYN, or stealth modes.
- No parallel scanning; ports are checked sequentially.
- A single scan cannot prove a firewall's behavior; `filtered` is an
  educated guess based on timeouts.

## Security considerations

- You are responsible for confirming authorization before every scan.
- Use localhost or private lab IPs for practice.
- The authorization warning shown by the CLI is intentional — read it.

## Authorized-use disclaimer

This tool is for educational purposes and authorized security testing only.
Do not scan systems you do not own or lack permission to test.
