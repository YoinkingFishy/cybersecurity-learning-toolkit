"""Command-line interface for the Python Port Scanner."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .exporters import save_to_csv, save_to_txt
from .scanner import PortScanner
from .validators import validate_port, validate_port_range, validate_target

AUTHORIZATION_WARNING = (
    "WARNING: Only scan systems you own or have explicit permission to test. "
    "Scanning unauthorized systems may be illegal in your jurisdiction."
)


def _parse_ports(value: str) -> List[int]:
    """Parse a comma-separated list of ports."""
    ports: List[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        ports.append(validate_port(int(item)))
    if not ports:
        raise argparse.ArgumentTypeError("no valid ports provided")
    return ports


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m port_scanner.cli",
        description="Educational TCP port scanner (authorized use only).",
    )
    parser.add_argument("--target", required=True, help="IP address or hostname to scan")
    parser.add_argument("--ports", type=_parse_ports, help="Comma-separated ports, e.g. 22,80,443")
    parser.add_argument("--start-port", type=int, help="First port of a range to scan")
    parser.add_argument("--end-port", type=int, help="Last port of a range to scan")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--output", help="Write results to this file")
    parser.add_argument("--format", choices=["txt", "csv"], default="txt", help="Output format (default: txt)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Run the port scanner CLI.

    Args:
        argv: Command-line arguments; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (0 on success, 1 on error).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.ports is None and (args.start_port is None or args.end_port is None):
        parser.error("provide --ports or both --start-port and --end-port")

    try:
        target = validate_target(args.target)
        if args.timeout <= 0:
            raise ValueError(f"timeout must be positive, got {args.timeout}")
        scanner = PortScanner(timeout=args.timeout)
        if args.ports is not None:
            results = scanner.scan_ports(target, args.ports)
        else:
            results = scanner.scan_range(target, args.start_port, args.end_port)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(AUTHORIZATION_WARNING)
    print()
    for result in results:
        print(f"  Port {int(result['port']):<5} {str(result['status']).upper()}")

    if args.output:
        try:
            if args.format == "csv":
                written = save_to_csv(results, args.output)
            else:
                written = save_to_txt(results, args.output)
            print(f"\nResults saved to: {written}")
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
