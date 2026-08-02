# FAQ

## Is this toolkit safe to use?

Yes. It is designed for education and authorized testing only. Every CLI
prints a warning about authorization before scanning or analyzing anything.

## Does the port scanner use stealth techniques?

No. The scanner performs plain TCP connect scans only. Stealth, evasion, and
fragmentation techniques are intentionally excluded.

## What log formats does the analyzer support?

Apache combined log format, syslog-style sshd auth logs, and Windows-style
CSV exports from `wevtutil` or PowerShell.

## Can the integrity checker protect against attackers?

A hash manifest detects unauthorized modification. It does not by itself
prove who made the change; keep the baseline manifest stored securely.

## Why MD5?

MD5 is included for educational comparison and legacy compatibility. Use
SHA-256 for real integrity checking.