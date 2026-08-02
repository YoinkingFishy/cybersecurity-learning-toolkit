"""Export log analysis reports to TXT, CSV, or JSON."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List


def _resolve_path(output_file: str) -> Path:
    """Return a Path, refusing to overwrite an existing file."""
    path = Path(output_file)
    if path.exists():
        raise FileExistsError(
            f"output file {output_file} already exists — choose a different "
            "name or delete it first"
        )
    return path


def _flatten_alerts(report: Dict[str, object]) -> List[List[str]]:
    """Flatten alerts into rows for CSV export."""
    rows: List[List[str]] = []
    for alert in report.get("failed_login_alerts", []):  # type: ignore[union-attr]
        rows.append(
            [
                "failed-login-burst",
                str(alert["ip"]),
                str(alert["failed_attempts"]),
                str(alert.get("time_window_minutes", "")),
                str(alert["severity"]),
            ]
        )
    for finding in report.get("unusual_activity_alerts", []):  # type: ignore[union-attr]
        rows.append(
            [
                "unusual-activity",
                str(finding["ip"]),
                str(finding["evidence"]),
                "",
                str(finding["severity"]),
            ]
        )
    return rows


def export_report_txt(report: Dict[str, object], output_file: str) -> str:
    """Write a human-readable text report."""
    path = _resolve_path(output_file)
    summary = report["summary"]  # type: ignore[assignment]
    lines = [
        "Cybersecurity Learning Toolkit",
        "Log Analysis Report",
        "=" * 29,
        "",
        f"Analyzed at : {report['analysis_timestamp']}",
        f"Input file  : {report['input_file']}",
        f"Log format  : {report['log_format']}",
        f"Total events: {report['total_events']}",
        "",
        "Summary",
        "-" * 29,
        f"Successful requests : {summary['successful_requests']}",
        f"Failed requests     : {summary['failed_requests']}",
        f"Unique IPs          : {summary['unique_ips']}",
        f"Most active IPs     : {summary['most_active_ips']}",
        "",
        "Failed-login burst alerts",
        "-" * 29,
    ]
    if not report["failed_login_alerts"]:  # type: ignore[truthy-dict]
        lines.append("None")
    else:
        for alert in report["failed_login_alerts"]:  # type: ignore[union-attr]
            lines.append(
                f"  {alert['ip']}: {alert['failed_attempts']} failures "
                f"(window: {alert.get('time_window_minutes', 'unknown')} min, "
                f"severity: {alert['severity']})"
            )
    lines.extend(
        [
            "",
            "Unusual activity alerts",
            "-" * 29,
        ]
    )
    if not report["unusual_activity_alerts"]:  # type: ignore[truthy-dict]
        lines.append("None")
    else:
        for finding in report["unusual_activity_alerts"]:  # type: ignore[union-attr]
            lines.append(f"  {finding['ip']}: {finding['finding']} ({finding['evidence']})")
    lines.extend(
        [
            "",
            "Recommended defensive actions",
            "-" * 29,
        ]
    )
    for action in report["recommended_actions"]:  # type: ignore[union-attr]
        lines.append(f"  - {action}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def export_report_csv(report: Dict[str, object], output_file: str) -> str:
    """Write alerts as CSV rows."""
    path = _resolve_path(output_file)
    rows = _flatten_alerts(report)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["alert_type", "ip", "evidence", "window_minutes", "severity"])
        writer.writerows(rows)
    return str(path)


def export_report_json(report: Dict[str, object], output_file: str) -> str:
    """Write the full report as JSON."""
    path = _resolve_path(output_file)
    path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    return str(path)
