# Beginner Challenge 1

## Platform

PicoCTF (authorized, public CTF platform)

## Difficulty

Easy

## Category

Cryptography

## Learning Objectives

- Recognize weak and outdated hash algorithms.
- Use a command-line hashing tool correctly.
- Understand why hash choice matters for integrity and password storage.

## Challenge Description

A practice challenge provides a file and its expected MD5 checksum. The goal
is to verify whether the file matches the checksum and recover the flag value
hidden in the verification process.

## Step 1 — Enumeration

- Downloaded the challenge file to the lab machine.
- The challenge description supplied a reference MD5 digest.

## Step 2 — Analysis

- Computed the file's hash using the toolkit:

  ```bash
  python -m file_integrity.cli hash challenge.bin --algorithm md5
  ```

- The computed digest matched the provided reference digest.

## Step 3 — Finding the Vulnerability

- The challenge used **MD5** as the integrity mechanism.
- MD5 is cryptographically broken: collisions are practical, and it is
  unsuitable for integrity or password storage.

## Step 4 — Exploitation in the Authorized Lab

- After verifying integrity, the file was inspected for embedded data.
- The flag `<FLAG>` was recovered from the file contents.
- (No attack was needed — the weakness was the algorithm choice itself.)

## Step 5 — Obtaining the Flag

- Flag captured: `<FLAG>` (value redacted)

## Step 6 — Lessons Learned

- "Checksum matches" is only as strong as the algorithm used.
- SHA-256 (or stronger) should be the default for integrity checking.
- Tools are only as trustworthy as the baselines they compare against.

## Remediation

- Replace MD5 with SHA-256 or a stronger hash family for integrity checks.
- For password storage, use a dedicated password-hashing scheme (e.g.,
  Argon2, bcrypt, scrypt) with per-user salts — never plain hashes.
- Prefer signed manifests (HMAC or digital signatures) so an attacker cannot
  silently update the baseline.

## Defensive Takeaways

- Audit existing systems for MD5-based checksum verification and upgrade them.
- Store manifests on trusted media and verify their own integrity.
- Educate teams on why hash algorithm choice matters operationally.

## References

- PicoCTF challenge page
- File Integrity Checker documentation in this repository
