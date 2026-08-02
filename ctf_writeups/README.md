# CTF Write-ups

A collection of step-by-step write-ups for beginner Capture The Flag (CTF)
challenges, organized by platform.

## Structure

```text
ctf_writeups/
├── README.md
├── tryhackme/
│   ├── README.md
│   └── beginner-room-1/
│       └── writeup.md
└── picoctf/
    ├── README.md
    └── beginner-challenge-1/
        └── writeup.md
```

## Write-up template

Every write-up follows the same structure:

1. Challenge Name
2. Platform
3. Difficulty
4. Category
5. Learning Objectives
6. Challenge Description
7. Step 1 — Enumeration
8. Step 2 — Analysis
9. Step 3 — Finding the Vulnerability
10. Step 4 — Exploitation in the Authorized Lab
11. Step 5 — Obtaining the Flag
12. Step 6 — Lessons Learned
13. Remediation
14. Defensive Takeaways
15. References

## Guidelines

- Only document challenges you are legally permitted to study.
- Write explanations in your own words — do not copy copyrighted solutions.
- Never publish real credentials, personal information, or secrets.
- Use placeholders (`<LAB_IP>`, `<USERNAME>`, `<PASSWORD>`, `<FLAG>`) instead
  of real values.
- Always include the **Remediation** and **Defensive Takeaways** sections:
  every attack should teach how defenders prevent it.

## Placeholder conventions

| Placeholder | Meaning                                  |
| ----------- | ---------------------------------------- |
| `<LAB_IP>`  | The lab/target machine address           |
| `<USERNAME>`| A test account name                      |
| `<PASSWORD>`| A test account password                  |
| `<FLAG>`    | The challenge flag value                 |
