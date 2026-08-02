# Write-up: Weak Hash Challenge (template)

- Challenge: Beginner Challenge 2
- Difficulty: Easy
- Theme: Recognising weak hashing schemes.

## Challenge

A sample service stored a value as an MD5 digest with no salt.

## Approach

1. Identify the hash type from its length (32 hex characters).
2. Look up the digest in a public rainbow table or hash it with common
   candidate words locally.
3. Document the plaintext and the reason the scheme is weak.

## Remediation

- Use a modern algorithm such as Argon2id for passwords.
- Always add a per-user salt.

## Defensive Takeaways

- Unsalting, fast hashes make offline cracking trivial.
- Length alone reveals the algorithm family; verify before trusting.
