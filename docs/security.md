# Security Considerations

## Purpose

This toolkit exists to teach security concepts in an **educational,
defensive, and authorized** context. It contains no offensive tooling:
no stealth scanning, no evasion, no exploit delivery, no credential theft.

## Authorized use only

You may run these tools only against:

- Systems you own.
- Systems where you have written permission from the owner.
- Official lab or CTF environments.

Scanning or analyzing systems without authorization may be illegal in many
jurisdictions. The operator — not the authors — is responsible for lawful use.

## Tool-specific notes

### Port scanner

- Performs plain TCP connects only. Results (`open`/`closed`/`filtered`) are
  best-effort and can be influenced by firewalls, NAT, and proxies.
- A `filtered` result is an inference from timeouts, not a firewall fact.
- Do not scan wide ranges of external systems automatically.

### Log analyzer

- Analyzes only the files you point it at — it performs no network access.
- Reports are heuristic ("potentially suspicious"), never definitive.
- Report files may contain IP addresses; treat them as sensitive.

### File integrity checker

- SHA-256 is the recommended algorithm; MD5 is provided for compatibility
  and education only (it is cryptographically weak).
- A hash proves a file changed — not who changed it, or why.
- Always verify against a **trusted baseline** stored separately from the
  files it protects.
- Do not trust a manifest obtained from the same location as the files.

## Secrets and privacy policy

The repository guarantees:

- No API keys, passwords, or personal data in code, docs, or examples.
- No real private IP addresses — samples use documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- `.env` and other secret files are ignored by `.gitignore`.
- CTF write-ups use placeholders (`<LAB_IP>`, `<FLAG>`, ...) instead of real
  values.

## Reporting issues

See [SECURITY.md](../SECURITY.md) for the responsible-disclosure process.
Never open a public issue for a security problem.
