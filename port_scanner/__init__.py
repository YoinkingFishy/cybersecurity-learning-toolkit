"""Python Port Scanner — educational TCP connect scanner.

Only for use against systems you own or are explicitly authorized to test.
"""

from .scanner import PortScanner
from .validators import validate_port, validate_port_range, validate_target

__all__ = ["PortScanner", "validate_port", "validate_port_range", "validate_target"]
__version__ = "1.0.0"
