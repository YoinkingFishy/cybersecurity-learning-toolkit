"""Log Analyzer — defensive log parsing and anomaly detection.

Analyzes locally supplied log files (Apache-style access logs,
authentication logs, and exported Windows event logs). No remote access.
"""

from .analyzer import analyze_log

__all__ = ["analyze_log"]
__version__ = "1.0.0"
