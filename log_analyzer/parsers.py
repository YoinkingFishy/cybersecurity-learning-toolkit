"""Log parsers for Apache-style, authentication, and Windows CSV logs.

Every parser is defensive and works only on locally supplied files. Parsers
return ``None`` for lines they cannot understand so callers can skip them
without crashing.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Dict, List, Optional

# Apache combined log format, e.g.:
# 192.168.1.10 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326
APACHE_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
)

# Syslog-style sshd authentication lines, e.g.:
# Jan  1 12:00:01 host sshd[1234]: Failed password for invalid user root from 192.168.1.10 port 22 ssh2
# Jan  1 12:00:02 host sshd[1234]: Accepted password for alice from 192.168.1.11 port 22 ssh2
SSHD_AUTH_RE = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+'
    r'sshd\[\d+\]:\s+'
    r'(?P<event>Failed password(?: for invalid user)?|Accepted password)\s+for\s+'
    r'(?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<ip>\S+)'
)

# Loose fallback for other authentication-style lines:
# <something> <event keyword> ... from <ip>
GENERIC_AUTH_RE = re.compile(
    r'^(?P<timestamp>\S+\s+\S+)\s+\S+\s+'
    r'(?P<event>Failed|Accepted|Authentication failure|authentication failure)\b.*?'
    r'from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

# Case-insensitive header aliases for exported Windows event logs (CSV).
_HEADER_ALIASES = {
    "timestamp": ("timecreated", "date and time", "timestamp", "datetime"),
    "ip": ("ipaddress", "ip address", "clientip", "client ip", "sourceip", "source ip", "ip"),
    "event": ("eventid", "event", "id", "eventcode"),
    "status": ("leveldisplayname", "level", "status", "severity"),
}


def _match_header(header: str, aliases) -> Optional[str]:
    """Return the canonical key whose alias matches ``header`` (case-insensitive)."""
    normalized = header.strip().lower().replace("_", " ").replace("-", " ")
    for canonical, candidates in aliases.items():
        if normalized in candidates:
            return canonical
    return None


def parse_apache_log_line(line: str) -> Optional[Dict[str, str]]:
    """Parse one line of an Apache-style access log.

    Args:
        line: A single log line (may include a trailing newline).

    Returns:
        A dict with ``ip``, ``timestamp``, ``method``, ``path``, ``status``,
        and ``size`` keys, or ``None`` if the line does not match.
    """
    match = APACHE_LOG_RE.match(line.rstrip("\r\n"))
    if not match:
        return None
    request = match.group("request")
    method, path = "", ""
    if request:
        parts = request.split()
        if parts:
            method = parts[0]
            path = parts[1] if len(parts) > 1 else ""
    return {
        "ip": match.group("ip"),
        "timestamp": match.group("timestamp"),
        "method": method,
        "path": path,
        "status": match.group("status"),
        "size": match.group("size"),
    }


def parse_generic_auth_log_line(line: str) -> Optional[Dict[str, str]]:
    """Parse one line of an authentication log (syslog/sshd style).

    Args:
        line: A single log line.

    Returns:
        A dict with ``timestamp``, ``ip``, ``username``, ``event``, and
        ``status`` keys, or ``None`` if the line does not match.
    """
    line = line.rstrip("\r\n")
    match = SSHD_AUTH_RE.match(line)
    if not match:
        match = GENERIC_AUTH_RE.match(line)
    if not match:
        return None
    event = match.group("event").lower()
    status = "failed" if "fail" in event or "failure" in event else "success"
    return {
        "timestamp": match.group("timestamp"),
        "ip": match.group("ip"),
        "username": match.groupdict().get("username", ""),
        "event": match.group("event"),
        "status": status,
    }


def parse_windows_csv_log(file_path: str) -> List[Dict[str, str]]:
    """Read exported Windows event logs from a CSV file.

    The CSV may use any common column naming; headers are matched
    case-insensitively by alias. Rows that cannot be read are skipped.

    Args:
        file_path: Path to the exported CSV file.

    Returns:
        A list of dicts with ``timestamp``, ``ip``, ``event``, and ``status``
        keys.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"log file not found: {file_path}")

    events: List[Dict[str, str]] = []
    with open(path, newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            return events
        column_map: Dict[str, str] = {}
        for header in reader.fieldnames:
            canonical = _match_header(header, _HEADER_ALIASES)
            if canonical:
                column_map[canonical] = header
        for row in reader:
            try:
                events.append(
                    {
                        "timestamp": row.get(column_map.get("timestamp", ""), ""),
                        "ip": row.get(column_map.get("ip", ""), ""),
                        "event": row.get(column_map.get("event", ""), ""),
                        "status": row.get(column_map.get("status", ""), ""),
                    }
                )
            except (KeyError, TypeError):
                continue
    return events
