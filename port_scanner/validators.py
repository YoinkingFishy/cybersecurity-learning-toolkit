"""Input validation helpers for the port scanner."""

from __future__ import annotations

import ipaddress
import re

MIN_PORT = 1
MAX_PORT = 65535

# Basic hostname validation: labels of alphanumerics and hyphens, dot separated.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.?$")


def _looks_like_broken_ip(value: str) -> bool:
    """Return True if every dot-separated label is numeric.

    A string like ``999.999.999.999`` is not a valid IP address and should
    not be treated as a hostname either.
    """
    if "." not in value:
        return False
    return all(part.isdigit() for part in value.split("."))


def validate_target(target: str) -> str:
    """Validate that ``target`` is a valid IP address or hostname.

    Args:
        target: The target string to validate.

    Returns:
        The normalized target.

    Raises:
        ValueError: If the target is neither a valid IP address nor hostname.
    """
    if not target or not isinstance(target, str):
        raise ValueError("target must be a non-empty string")
    value = target.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if _HOSTNAME_RE.match(value) and not _looks_like_broken_ip(value):
            return value
    raise ValueError(
        f"invalid target {target!r}: must be a valid IP address or hostname"
    )


def validate_port(port: int) -> int:
    """Validate that ``port`` is between 1 and 65535.

    Args:
        port: Port number to validate.

    Returns:
        The validated port.

    Raises:
        ValueError: If the port is outside the valid range.
    """
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError(f"port must be an integer, got {port!r}")
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(
            f"port must be between {MIN_PORT} and {MAX_PORT}, got {port}"
        )
    return port


def validate_port_range(start_port: int, end_port: int) -> None:
    """Validate a port range.

    Args:
        start_port: First port of the range.
        end_port: Last port of the range.

    Raises:
        ValueError: If any port is out of range or start exceeds end.
    """
    validate_port(start_port)
    validate_port(end_port)
    if start_port > end_port:
        raise ValueError(
            f"start_port ({start_port}) must not be greater than "
            f"end_port ({end_port})"
        )
