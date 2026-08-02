# Write-up: Vulnerable HTTP Service (template)

- Room: Beginner Room 2
- Difficulty: Easy
- Goal: Exploit a known vulnerability in a sample service, then document remediation.

## Enumeration

`
nmap -sV <LAB_IP>
`

## Vulnerability

A sample web service exposed a directory listing and default credentials.

## Exploitation

1. Connect with the sample credentials.
2. Upload a harmless file and confirm the write path.
3. Document the exposure with screenshots.

## Remediation

- Disable directory listing on the web server.
- Replace default credentials before deployment.
- Restrict uploads to validated file types.

## Defensive Takeaways

- Default credentials are the most common initial-access vector.
- Always test your own services the way an attacker would.
