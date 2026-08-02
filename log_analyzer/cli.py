"""Command-line interface for the Log Analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from .analyzer import SUPPORTED_FORMATS, analyze_log
from .exporters import export_report_csv, export_report_json, export_report_txt


def _detect_format(file_path: str) -> str:
    """Guess the log format from the file extension when not specified."""
    suffix = Path(file_path).suffix.lower()
    if suffix == ".csv":
        return "windows-csv"
    return "apache"


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m log_analyzer.cli",
        description="Defensive log analysis tool (analyze local logs only).",
    )
    parser.add_argument("--file", required=True, help="Path to the log file to analyze")
    parser.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        default=None,
        help="Log format; auto-detected when omitted (.csv -> windows-csv)",
    )
    parser.add_argument(
        "--threshold", type=int, default=5, help="Failed logins to flag as a burst (default: 5)"
    )
    parser.add_argument(
        "--window", type=int, default=10, help="Burst time window in minutes (default: 10)"
    )
    parser.add_argument("--output", help="Write the report to this file (.txt/.csv/.json)")
    return parser


def main(argv: Optional[list] = None) -> int:
    """Run the log analyzer CLI.

    Returns:
        Process exit code (0 on success, 1 on error).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if not Path(args.file).is_file():
        print(f"error: log file not found: {args.file}", file=sys.stderr)
        return 1
    if args.threshold <= 0:
        print(f"error: threshold must be positive, got {args.threshold}", file=sys.stderr)
        return 1

    log_format = args.format or _detect_format(args.file)
    try:
        report = analyze_log(
            args.file,
            log_format=log_format,
            failed_threshold=args.threshold,
            window_minutes=args.window,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    summary = report["summary"]  # type: ignore[assignment]
    print(f"Analyzed {report['input_file']} ({report['log_format']})")
    print(f"  Total events : {report['total_events']}")
    print(f"  Unique IPs   : {summary['unique_ips']}")
    print(f"  Failed login : {len(report['failed_login_alerts'])} burst alert(s)")  # type: ignore[arg-type]
    print(f"  Unusual IPs  : {len(report['unusual_activity_alerts'])} finding(s)")  # type: ignore[arg-type]

    if args.output:
        try:
            suffix = Path(args.output).suffix.lower()
            if suffix == ".csv":
                written = export_report_csv(report, args.output)
            elif suffix == ".json":
                written = export_report_json(report, args.output)
            else:
                written = export_report_txt(report, args.output)
            print(f"Report saved to: {written}")
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
