"""Tests for the Python Port Scanner (fully offline)."""

from __future__ import annotations

import os
import socket
import tempfile
import unittest

from port_scanner import exporters
from port_scanner.scanner import PortScanner
from port_scanner.validators import (
    validate_port,
    validate_port_range,
    validate_target,
)


def _start_listener(port: int = 0) -> socket.socket:
    """Bind a TCP listener on 127.0.0.1 and return the socket."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    return srv


class PortScannerInitTests(unittest.TestCase):
    def test_accepts_positive_timeout(self) -> None:
        scanner = PortScanner(timeout=0.5)
        self.assertEqual(scanner.timeout, 0.5)

    def test_rejects_non_positive_timeout(self) -> None:
        for bad in (0, -1, -0.1):
            with self.assertRaises(ValueError):
                PortScanner(timeout=bad)


class TargetValidationTests(unittest.TestCase):
    def test_accepts_ip_address(self) -> None:
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")

    def test_accepts_hostname(self) -> None:
        self.assertEqual(validate_target("localhost"), "localhost")

    def test_rejects_invalid_target(self) -> None:
        for bad in ("", "not a host!", "999.999.999.999", None):
            with self.assertRaises(ValueError):
                validate_target(bad)


class PortValidationTests(unittest.TestCase):
    def test_accepts_boundary_ports(self) -> None:
        validate_port(1)
        validate_port(65535)

    def test_rejects_out_of_bounds_ports(self) -> None:
        for bad in (0, 65536, -1):
            with self.assertRaises(ValueError):
                validate_port(bad)

    def test_rejects_non_integer_ports(self) -> None:
        for bad in ("22", None, 22.5):
            with self.assertRaises(ValueError):
                validate_port(bad)

    def test_rejects_reversed_range(self) -> None:
        with self.assertRaises(ValueError):
            validate_port_range(80, 79)

    def test_accepts_valid_range(self) -> None:
        validate_port_range(1, 100)


class ScanBehaviourTests(unittest.TestCase):
    def test_scan_open_port(self) -> None:
        srv = _start_listener()
        try:
            port = srv.getsockname()[1]
            result = PortScanner(timeout=1.0).scan_port("127.0.0.1", port)
            self.assertEqual(result["status"], "open")
            self.assertEqual(result["port"], port)
            self.assertEqual(result["target"], "127.0.0.1")
        finally:
            srv.close()

    def test_scan_closed_port(self) -> None:
        srv = _start_listener()
        port = srv.getsockname()[1]
        srv.close()
        result = PortScanner(timeout=0.5).scan_port("127.0.0.1", port)
        self.assertIn(result["status"], ("closed", "filtered"))
        self.assertNotEqual(result["status"], "open")

    def test_scan_ports_list(self) -> None:
        srv = _start_listener()
        try:
            port = srv.getsockname()[1]
            results = PortScanner(timeout=0.5).scan_ports("127.0.0.1", [port])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "open")
        finally:
            srv.close()

    def test_scan_ports_rejects_invalid_target(self) -> None:
        with self.assertRaises(ValueError):
            PortScanner().scan_ports("not a host!", [80])

    def test_scan_range(self) -> None:
        srv = _start_listener()
        try:
            port = srv.getsockname()[1]
            results = PortScanner(timeout=0.5).scan_range("127.0.0.1", port, port)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "open")
        finally:
            srv.close()

    def test_scan_range_rejects_invalid_range(self) -> None:
        with self.assertRaises(ValueError):
            PortScanner().scan_range("127.0.0.1", 100, 1)
        with self.assertRaises(ValueError):
            PortScanner().scan_range("127.0.0.1", 0, 10)


class ExporterTests(unittest.TestCase):
    def _results(self):
        return [
            {"target": "127.0.0.1", "port": 22, "status": "open"},
            {"target": "127.0.0.1", "port": 80, "status": "closed"},
        ]

    def test_save_to_txt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "results.txt")
            written = exporters.save_to_txt(self._results(), path)
            self.assertTrue(os.path.exists(written))
            with open(written, encoding="utf-8") as handle:
                content = handle.read()
            self.assertIn("Target: 127.0.0.1", content)
            self.assertIn("Port 22    OPEN", content)
            self.assertIn("Port 80    CLOSED", content)

    def test_save_to_csv(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "results.csv")
            written = exporters.save_to_csv(self._results(), path)
            with open(written, encoding="utf-8") as handle:
                content = handle.read()
            self.assertTrue(content.startswith("target,port,status"))
            self.assertIn("127.0.0.1,22,open", content)

    def test_refuses_to_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "results.txt")
            exporters.save_to_txt(self._results(), path)
            with self.assertRaises(FileExistsError):
                exporters.save_to_txt(self._results(), path)


if __name__ == "__main__":
    unittest.main()
