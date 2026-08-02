"""TCP connect scanner built on the standard :mod:`socket` library.

This scanner performs a plain TCP connect to each port. It has no stealth,
evasion, or packet-crafting features. Use it only against systems you own or
have explicit authorization to test.
"""

from __future__ import annotations

import errno
import socket
from typing import Dict, List

from .validators import validate_port, validate_port_range, validate_target

_STATUS_OPEN = "open"
_STATUS_CLOSED = "closed"
_STATUS_FILTERED = "filtered"
_STATUS_ERROR = "error"

_ERRNO_CLOSED = frozenset({errno.ECONNREFUSED, errno.ENETUNREACH})
_ERRNO_FILTERED = frozenset({errno.EHOSTUNREACH, errno.ETIMEDOUT})


class PortScanner:
    """A simple, safe TCP connect port scanner."""

    def __init__(self, timeout: float = 1.0) -> None:
        """Initialize the scanner with a socket timeout.

        Args:
            timeout: Connection timeout in seconds; must be positive.

        Raises:
            ValueError: If ``timeout`` is not positive.
        """
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout!r}")
        self.timeout = timeout

    def scan_port(self, target: str, port: int) -> Dict[str, object]:
        """Attempt a TCP connection to a single port.

        Args:
            target: IP address or hostname to scan.
            port: Port number between 1 and 65535.

        Returns:
            A dict with ``target``, ``port``, and ``status`` keys. Status is
            one of ``"open"``, ``"closed"``, ``"filtered"``, or ``"error"``.
            This method never raises for unreachable or refused connections.

        Raises:
            ValueError: If the port is invalid.
        """
        validate_port(port)
        status = _STATUS_ERROR
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    status = _STATUS_OPEN
                elif result in _ERRNO_CLOSED:
                    status = _STATUS_CLOSED
                elif result in _ERRNO_FILTERED:
                    status = _STATUS_FILTERED
                else:
                    status = _STATUS_CLOSED
        except socket.timeout:
            status = _STATUS_FILTERED
        except OSError as exc:
            if exc.errno in _ERRNO_CLOSED:
                status = _STATUS_CLOSED
            elif exc.errno in _ERRNO_FILTERED:
                status = _STATUS_FILTERED
            else:
                status = _STATUS_ERROR
        return {"target": target, "port": port, "status": status}

    def scan_ports(self, target: str, ports: List[int]) -> List[Dict[str, object]]:
        """Scan a list of ports and return one result dict per port.

        Args:
            target: IP address or hostname to scan.
            ports: Iterable of port numbers.

        Returns:
            List of scan result dicts, one per port.
        """
        validate_target(target)
        results: List[Dict[str, object]] = []
        for port in ports:
            results.append(self.scan_port(target, port))
        return results

    def scan_range(
        self, target: str, start_port: int, end_port: int
    ) -> List[Dict[str, object]]:
        """Scan every port in ``[start_port, end_port]`` inclusive.

        Args:
            target: IP address or hostname to scan.
            start_port: First port of the range.
            end_port: Last port of the range.

        Returns:
            List of scan result dicts.

        Raises:
            ValueError: If the range is invalid (out of bounds or reversed).
        """
        validate_target(target)
        validate_port_range(start_port, end_port)
        return self.scan_ports(target, list(range(start_port, end_port + 1)))
