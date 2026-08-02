# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this repository or its tools,
please report it privately so it can be addressed before public disclosure.

**Do not open a public issue for security problems.**

Send your report to: wagdemehul@gmail.com

Please include:

- A description of the issue and the impact you observed
- Steps to reproduce the problem
- Affected versions or files, if known
- Any relevant logs, but **no secrets or personal data**

We will acknowledge your report within 48 hours and will keep you informed of
progress until it is resolved.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| older   | :x:                |

## Scope

This repository is educational software. Security issues that are out of scope
include general misuse of the tools (for example, scanning systems without
authorization) — those are addressed by the project's security disclaimer and
ethical guidelines rather than by patches.

## Security Notes

- The toolkit uses only Python's standard library.
- No API keys, passwords, or personal data are stored anywhere in the code.
- Hash values are for integrity checking only — a hash does not prove who
  modified a file, and verification requires a trusted baseline.
