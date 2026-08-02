"""Export port scan results to text or CSV files."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List

_HEADER = "Cybersecurity Learning Toolkit"


def _resolve_path(output_file: str) -> Path:
    """Return a Path, refusing to overwrite an existing file."""
    path = Path(output_file)
    if path.exists():
        raise FileExistsError(
            f"output file {output_file} already exists — choose a different "
            "name or delete it first"
        )
    return path


def save_to_txt(results: List[Dict[str, object]], output_file: str) -> str:
    """Write scan results as a clean, human-readable text report.

    Args:
        results: List of scan result dicts (``target``, ``port``, ``status``).
        output_file: Destination file path.

    Returns:
        The path of the written file.

    Raises:
        FileExistsError: If ``output_file`` already exists.
    """
    path = _resolve_path(output_file)
    target = results[0]["target"] if results else ""
    lines = [
        _HEADER,
        "Port Scan Results",
        "=" * 29,
        "",
        f"Target: {target}",
        "",
    ]
    for result in results:
        lines.append(
            f"Port {int(result['port']):<5} {str(result['status']).upper()}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def save_to_csv(results: List[Dict[str, object]], output_file: str) -> str:
    """Write scan results as CSV with columns ``target,port,status``.

    Args:
        results: List of scan result dicts.
        output_file: Destination file path.

    Returns:
        The path of the written file.

    Raises:
        FileExistsError: If ``output_file`` already exists.
    """
    path = _resolve_path(output_file)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["target", "port", "status"])
        for result in results:
            writer.writerow(
                [result["target"], int(result["port"]), result["status"]]
            )
    return str(path)
