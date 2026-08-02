"""Tests for the Log Analyzer (fully offline)."""

from __future__ import annotations

import os
import tempfile
import unittest

from log_analyzer.analyzer import analyze_log
from log_analyzer.detectors import (
    detect_failed_login_bursts,
    detect_unusual_ip_activity,
    summarize_ip_activity,
)
from log_analyzer.parsers import (
    parse_apache_log_line,
    parse_generic_auth_log_line,
    parse_windows_csv_log,
)

VALID_APACHE = (
    '192.0.2.10 - - [02/Aug/2026:09:00:01 +0000] "GET /index.html HTTP/1.1" 200 5120'
)
AUTH_FAILED = (
    "Aug  2 09:01:02 labhost sshd[1235]: Failed password for invalid user "
    "root from 203.0.113.5 port 22 ssh2"
)
AUTH_ACCEPTED = (
    "Aug  2 09:00:01 labhost sshd[1234]: Accepted password for alice "
    "from 192.0.2.10 port 22 ssh2"
)


class ApacheParserTests(unittest.TestCase):
    def test_parses_valid_line(self) -> None:
        parsed = parse_apache_log_line(VALID_APACHE)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["ip"], "192.0.2.10")
        self.assertEqual(parsed["method"], "GET")
        self.assertEqual(parsed["path"], "/index.html")
        self.assertEqual(parsed["status"], "200")
        self.assertEqual(parsed["size"], "5120")

    def test_returns_none_for_invalid_line(self) -> None:
        for bad in ("", "not a log line", "GET / HTTP/1.1 200 100"):
            self.assertIsNone(parse_apache_log_line(bad))


class AuthParserTests(unittest.TestCase):
    def test_parses_failed_login(self) -> None:
        parsed = parse_generic_auth_log_line(AUTH_FAILED)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["ip"], "203.0.113.5")
        self.assertEqual(parsed["username"], "root")
        self.assertEqual(parsed["status"], "failed")

    def test_parses_accepted_login(self) -> None:
        parsed = parse_generic_auth_log_line(AUTH_ACCEPTED)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["ip"], "192.0.2.10")
        self.assertEqual(parsed["username"], "alice")
        self.assertEqual(parsed["status"], "success")

    def test_returns_none_for_invalid_line(self) -> None:
        self.assertIsNone(parse_generic_auth_log_line("some unrelated line"))
        self.assertIsNone(parse_generic_auth_log_line(""))


class WindowsCsvParserTests(unittest.TestCase):
    def test_parses_exported_csv(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "events.csv")
            with open(path, "w", newline="", encoding="utf-8") as handle:
                handle.write(
                    "TimeCreated,IpAddress,EventID,LevelDisplayName\r\n"
                    "2026-08-02T09:00:00,203.0.113.5,4625,Error\r\n"
                    "2026-08-02T09:05:00,192.0.2.10,4624,Information\r\n"
                )
            events = parse_windows_csv_log(path)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0]["ip"], "203.0.113.5")
            self.assertEqual(events[0]["event"], "4625")

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            parse_windows_csv_log("does-not-exist.csv")


class BurstDetectionTests(unittest.TestCase):
    def _failed_events(self, count: int, ip: str = "203.0.113.5") -> list:
        events = []
        for i in range(count):
            events.append(
                {
                    "timestamp": f"Aug  2 09:01:{i % 60:02d}",
                    "ip": ip,
                    "username": "root",
                    "status": "failed",
                }
            )
        return events

    def test_detects_burst_above_threshold(self) -> None:
        alerts = detect_failed_login_bursts(self._failed_events(8), threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "203.0.113.5")
        self.assertEqual(alerts[0]["failed_attempts"], 8)
        self.assertEqual(alerts[0]["time_window_minutes"], 10)
        self.assertEqual(alerts[0]["severity"], "medium")

    def test_high_burst_is_high_severity(self) -> None:
        alerts = detect_failed_login_bursts(self._failed_events(12), threshold=5)
        self.assertEqual(alerts[0]["severity"], "high")

    def test_ignores_burst_below_threshold(self) -> None:
        self.assertEqual(detect_failed_login_bursts(self._failed_events(3)), [])

    def test_empty_events(self) -> None:
        self.assertEqual(detect_failed_login_bursts([]), [])

    def test_ignores_successful_logins(self) -> None:
        events = [{"ip": "192.0.2.10", "status": "success"} for _ in range(10)]
        self.assertEqual(detect_failed_login_bursts(events), [])


class UnusualActivityTests(unittest.TestCase):
    def _apache_event(self, ip: str, path: str, status: str) -> dict:
        return {"ip": ip, "path": path, "status": status, "method": "GET"}

    def test_flags_many_4xx_responses(self) -> None:
        events = [self._apache_event("203.0.113.9", "/", "404") for _ in range(20)]
        findings = detect_unusual_ip_activity(events)
        self.assertTrue(
            any("4xx" in f["finding"] for f in findings),
            "expected a 4xx finding",
        )

    def test_flags_unusual_paths(self) -> None:
        events = [
            self._apache_event("203.0.113.9", "/admin", "404"),
            self._apache_event("203.0.113.9", "/.env", "404"),
            self._apache_event("203.0.113.9", "/config.php", "404"),
            self._apache_event("203.0.113.9", "/passwd", "404"),
            self._apache_event("203.0.113.9", "/wp-admin", "404"),
        ]
        findings = detect_unusual_ip_activity(events)
        self.assertTrue(
            any("unusual paths" in f["finding"] for f in findings),
            "expected an unusual-paths finding",
        )

    def test_flags_failed_auth_frequency(self) -> None:
        events = [{"ip": "203.0.113.5", "status": "failed"} for _ in range(6)]
        findings = detect_unusual_ip_activity(events)
        self.assertTrue(
            any("authentication" in f["finding"] for f in findings)
        )


class SummaryTests(unittest.TestCase):
    def test_summarizes_counts(self) -> None:
        events = [
            {"ip": "192.0.2.1", "status": "success"},
            {"ip": "192.0.2.1", "status": "success"},
            {"ip": "192.0.2.2", "status": "failed"},
        ]
        summary = summarize_ip_activity(events)
        self.assertEqual(summary["total_requests"], 3)
        self.assertEqual(summary["successful_requests"], 2)
        self.assertEqual(summary["failed_requests"], 1)
        self.assertEqual(summary["unique_ips"], 2)
        self.assertEqual(summary["most_active_ips"][0], ("192.0.2.1", 2))


class AnalyzerTests(unittest.TestCase):
    def _write_log(self, td: str, content: str, name: str = "log.txt") -> str:
        path = os.path.join(td, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_analyzes_apache_log(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._write_log(
                td, VALID_APACHE + "\n" + VALID_APACHE + "\ninvalid line\n"
            )
            report = analyze_log(path, log_format="apache")
            self.assertEqual(report["total_events"], 2)
            self.assertIn("failed_login_alerts", report)
            self.assertIn("recommended_actions", report)
            self.assertTrue(report["recommended_actions"])

    def test_analyzes_auth_log(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._write_log(td, AUTH_FAILED + "\n" + AUTH_ACCEPTED + "\n")
            report = analyze_log(path, log_format="auth")
            self.assertEqual(report["total_events"], 2)
            self.assertEqual(report["summary"]["unique_ips"], 2)

    def test_empty_log_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._write_log(td, "")
            report = analyze_log(path, log_format="apache")
            self.assertEqual(report["total_events"], 0)
            self.assertEqual(report["failed_login_alerts"], [])
            self.assertEqual(report["unusual_activity_alerts"], [])

    def test_unsupported_format_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = self._write_log(td, "x")
            with self.assertRaises(ValueError):
                analyze_log(path, log_format="unknown")

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            analyze_log("does-not-exist.log")

    def test_windows_csv_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "events.csv")
            with open(path, "w", newline="", encoding="utf-8") as handle:
                handle.write(
                    "TimeCreated,IpAddress,EventID,LevelDisplayName\r\n"
                    "2026-08-02T09:00:00,203.0.113.5,4625,Error\r\n"
                )
            report = analyze_log(path, log_format="windows-csv")
            self.assertEqual(report["total_events"], 1)


if __name__ == "__main__":
    unittest.main()
