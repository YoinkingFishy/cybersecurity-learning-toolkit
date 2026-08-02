# Roadmap

Planned work, roughly in priority order.

## Short term

- [x] Core toolkit: port scanner, log analyzer, file integrity checker.
- [x] Offline test suite covering all modules.
- [x] Sample logs and manifests under examples/.
- [ ] Extra parsers (nginx, JSON logs).

## Medium term

- [ ] Threat-hunting notebook tying the three tools together.
- [ ] Report templates for incident write-ups.

## Long term

- [ ] Optional YARA-style rule matching for log lines.

## Non-goals

- No offensive or stealth capabilities.
- No remote scanning by default; scan local and authorized targets only.
