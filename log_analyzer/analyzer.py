"""High-level analysis pipeline for the log analyzer."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .detectors import (
    build_recommended_actions,
    detect_failed_login_bursts,
    detect_unusual_ip_activity,
    summarize_ip_activity,
)
from .parsers import (
    parse_apache_log_line,
    parse_generic_auth_log_line,
    parse_windows_csv_log,
)

logger = logging.getLogger(__name__)

SUPPORTED_FORMATS = ("apache", "auth", "windows-csv")


def _parse_events(file_path: str, log_format: str) -> List[Dict[str, str]]:
    """Parse every line of the input file using the selected format parser."""
    events: List[Dict[str, str]] = []
    if log_format == "windows-csv":
        return parse_windows_csv_log(file_path)
    parser = (
        parse_apache_log_line if log_format == "apache" else parse_generic_auth_log_line
    )
    with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            parsed = parser(line)
            if parsed is not None:
                events.append(parsed)
            else:
                logger.debug("skipping unparseable line %d", line_number)
    return events


def analyze_log(
    file_path: str,
    log_format: str = "apache",
    failed_threshold: int = 5,
    window_minutes: int = 10,
) -> Dict[str, object]:
    """Analyze a local log file and produce a complete report.

    Args:
        file_path: Path to the log file to analyze.
        log_format: One of ``"apache"``, ``"auth"``, or ``"windows-csv"``.
        failed_threshold: Minimum failed logins to flag as a burst.
        window_minutes: Time window for burst detection.

    Returns:
        A report dict containing the analysis timestamp, input file, event
        totals, alerts, summary, and recommended defensive actions.

    Raises:
        ValueError: If ``log_format`` is unsupported.
        FileNotFoundError: If the input file does not exist.
    """
    if log_format not in SUPPORTED_FORMATS:
        raise ValueError(
            f"unsupported log format {log_format!r}; expected one of {SUPPORTED_FORMATS}"
        )
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"log file not found: {file_path}")

    events = _parse_events(str(path), log_format)
    burst_alerts = detect_failed_login_bursts(
        events, threshold=failed_threshold, window_minutes=window_minutes
    )
    unusual_findings = detect_unusual_ip_activity(events)
    summary = summarize_ip_activity(events)

    report: Dict[str, object] = {
        "analysis_timestamp": datetime.now().isoformat(timespec="seconds"),
        "input_file": str(path),
        "log_format": log_format,
        "total_events": summary["total_requests"],
        "failed_login_alerts": burst_alerts,
        "unusual_activity_alerts": unusual_findings,
        "summary": summary,
        "recommended_actions": build_recommended_actions(
            burst_alerts, unusual_findings
        ),
    }
    return report
