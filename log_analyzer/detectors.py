"""Detection engine for the log analyzer.

All findings are phrased as *suspicions* ("potentially suspicious",
"requires investigation", "unusual activity detected") — this tool never
labels activity as malicious with certainty.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

_UNUSUAL_PATH_PATTERNS = ("admin", "wp-admin", ".php", "..%2f", "%00", "passwd", "config", ".env")

# Heuristic thresholds (tunable).
FAILED_LOGIN_BURST_THRESHOLD = 5
FAILED_AUTH_FLAG_THRESHOLD = 5
HTTP_4XX_FLAG_THRESHOLD = 20
REQUEST_FREQUENCY_FLAG_THRESHOLD = 100
UNUSUAL_PATH_FLAG_THRESHOLD = 5


def _parse_timestamp(raw: str) -> Optional[datetime]:
    """Best-effort parse of common log timestamp formats."""
    raw = raw.strip()
    if not raw:
        return None
    formats = (
        "%d/%b/%Y:%H:%M:%S %z",   # Apache: 10/Oct/2000:13:55:36 -0700
        "%Y-%m-%d %H:%M:%S",      # ISO-like
        "%Y-%m-%dT%H:%M:%S",      # ISO
        "%Y-%m-%dT%H:%M:%S%z",
        "%b %d %H:%M:%S",         # syslog: Jan  1 12:00:01
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(raw, fmt)
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=datetime.now().year)
            return parsed
        except ValueError:
            continue
    return None


def detect_failed_login_bursts(
    events: List[Dict[str, str]],
    threshold: int = FAILED_LOGIN_BURST_THRESHOLD,
    window_minutes: int = 10,
) -> List[Dict[str, object]]:
    """Detect bursts of failed logins per source IP within a time window.

    Args:
        events: Parsed log events (dicts with at least ``ip`` and ``status``).
        threshold: Minimum failures to consider a burst.
        window_minutes: Time window used to group failures.

    Returns:
        A list of alerts like::

            {
                "ip": "192.168.1.10",
                "failed_attempts": 8,
                "time_window_minutes": 10,
                "severity": "medium",
            }

        If timestamps cannot be parsed, the total count per IP is used with a
        window reported as ``None``.
    """
    by_ip: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for event in events:
        if event.get("status") == "failed":
            by_ip[event.get("ip", "")].append(event)

    alerts: List[Dict[str, object]] = []
    for ip, failed_events in by_ip.items():
        if not ip or len(failed_events) < threshold:
            continue
        window = None
        count = len(failed_events)
        timestamps = [
            parsed
            for parsed in (_parse_timestamp(e.get("timestamp", "")) for e in failed_events)
            if parsed is not None
        ]
        if len(timestamps) == len(failed_events) and timestamps:
            timestamps.sort()
            for start in timestamps:
                end = start + timedelta(minutes=window_minutes)
                in_window = sum(1 for ts in timestamps if start <= ts <= end)
                if in_window >= threshold:
                    window = window_minutes
                    count = in_window
                    break
        severity = "high" if count >= threshold * 2 else "medium"
        alerts.append(
            {
                "ip": ip,
                "failed_attempts": count,
                "time_window_minutes": window,
                "severity": severity,
            }
        )
    return alerts


def detect_unusual_ip_activity(events: List[Dict[str, str]]) -> List[Dict[str, object]]:
    """Flag IPs showing potentially unusual patterns.

    Looks for high request frequency, many failed authentications, many 4xx
    responses, and repeated access to unusual paths.

    Args:
        events: Parsed log events.

    Returns:
        A list of findings, each with ``ip``, ``finding``, ``severity``, and
        ``evidence``. Findings use cautious, non-accusatory language.
    """
    per_ip: Dict[str, Dict[str, object]] = defaultdict(
        lambda: {
            "total": 0,
            "failed_auth": 0,
            "http_4xx": 0,
            "unusual_paths": Counter(),
        }
    )

    for event in events:
        ip = event.get("ip", "")
        if not ip:
            continue
        stats = per_ip[ip]
        stats["total"] += 1
        if event.get("status") == "failed":
            stats["failed_auth"] += 1
        status = str(event.get("status", ""))
        if status.isdigit() and 400 <= int(status) < 500:
            stats["http_4xx"] += 1
        path = event.get("path", "").lower()
        if any(pattern in path for pattern in _UNUSUAL_PATH_PATTERNS):
            stats["unusual_paths"][path] += 1

    findings: List[Dict[str, object]] = []
    for ip, stats in per_ip.items():
        failed = int(stats["failed_auth"])
        four_xx = int(stats["http_4xx"])
        total = int(stats["total"])
        unusual = sum(stats["unusual_paths"].values())

        if failed >= FAILED_AUTH_FLAG_THRESHOLD:
            findings.append(
                {
                    "ip": ip,
                    "finding": "Multiple failed authentication attempts — potentially suspicious",
                    "severity": "medium",
                    "evidence": f"{failed} failed attempts",
                }
            )
        if four_xx >= HTTP_4XX_FLAG_THRESHOLD:
            findings.append(
                {
                    "ip": ip,
                    "finding": "High number of client errors (HTTP 4xx) — requires investigation",
                    "severity": "medium",
                    "evidence": f"{four_xx} 4xx responses",
                }
            )
        if total >= REQUEST_FREQUENCY_FLAG_THRESHOLD:
            findings.append(
                {
                    "ip": ip,
                    "finding": "Unusually high request frequency — requires investigation",
                    "severity": "low",
                    "evidence": f"{total} requests",
                }
            )
        if unusual >= UNUSUAL_PATH_FLAG_THRESHOLD:
            findings.append(
                {
                    "ip": ip,
                    "finding": "Repeated access to unusual paths — unusual activity detected",
                    "severity": "medium",
                    "evidence": f"{unusual} hits on suspicious paths",
                }
            )
    return findings


def summarize_ip_activity(events: List[Dict[str, str]]) -> Dict[str, object]:
    """Summarize overall activity across all events.

    Args:
        events: Parsed log events.

    Returns:
        A dict with total/successful/failed counts, unique IP count, and the
        most active IPs.
    """
    total = len(events)
    successful = sum(1 for e in events if e.get("status") == "success")
    failed = sum(1 for e in events if e.get("status") == "failed")
    ip_counter = Counter(e.get("ip", "") for e in events if e.get("ip"))
    return {
        "total_requests": total,
        "successful_requests": successful,
        "failed_requests": failed,
        "unique_ips": len(ip_counter),
        "most_active_ips": ip_counter.most_common(5),
    }


def build_recommended_actions(
    burst_alerts: List[Dict[str, object]],
    unusual_findings: List[Dict[str, object]],
) -> List[str]:
    """Translate alerts into concrete defensive recommendations."""
    actions: List[str] = []
    if burst_alerts:
        actions.append(
            "Enable account lockout or rate limiting for authentication endpoints."
        )
        actions.append("Enforce strong password policies and multi-factor authentication (MFA).")
        actions.append("Review and block the source IPs flagged for failed-login bursts.")
    if unusual_findings:
        actions.append("Investigate flagged source IPs in firewall and IDS/IPS logs.")
        actions.append("Monitor and restrict access to sensitive or administrative paths.")
        actions.append("Review web server configuration and consider WAF rules for path probing.")
    if not actions:
        actions.append("No immediate action required — continue routine log monitoring.")
    return actions
