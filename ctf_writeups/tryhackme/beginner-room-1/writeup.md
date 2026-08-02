# Beginner Room 1

## Platform

TryHackMe (authorized lab environment)

## Difficulty

Easy

## Category

Web Application Basics

## Learning Objectives

- Enumerate a web application with basic tools.
- Understand how default credentials and weak authentication work.
- Learn how the same findings lead to a defensive fix.

## Challenge Description

A small practice web app is deployed on a lab machine. The goal is to find the
flag stored behind an administrative area protected only by default
credentials.

## Step 1 — Enumeration

- Started with a port scan of the lab host:

  ```bash
  python -m port_scanner.cli --target <LAB_IP> --ports 22,80,443
  ```

- Port 80 was open, hosting the practice application.
- Browsing to `/robots.txt` revealed a `/admin` path.

## Step 2 — Analysis

- The admin login page used a standard HTML form (`POST` to `/admin/login`).
- Reviewing the page source showed a hidden hint comment referencing a
  default account.

## Step 3 — Finding the Vulnerability

- The application accepted the default credentials
  `<USERNAME>` / `<PASSWORD>`.
- Root cause: default credentials left unchanged after installation.

## Step 4 — Exploitation in the Authorized Lab

- Logged in with the default account inside the lab environment.
- The admin panel exposed the flag value `<FLAG>` on an otherwise
  inaccessible page.

## Step 5 — Obtaining the Flag

- Flag captured: `<FLAG>`
- (Flag value redacted; never publish real flags.)

## Step 6 — Lessons Learned

- Always enumerate (ports, robots.txt, source comments) before guessing.
- Default credentials are one of the most common real-world findings.
- CTF practice directly maps to real systems: the same login page exists in
  production deployments everywhere.

## Remediation

- Force password changes on first login after installation.
- Enforce strong password policies and MFA for administrative accounts.
- Implement account lockout or rate limiting on login endpoints.
- Remove default accounts entirely, or disable them until explicitly
  configured.

## Defensive Takeaways

- Maintain an asset inventory and check every installed service for default
  credentials.
- Add default-credential checks to vulnerability scans.
- Restrict administrative interfaces to trusted networks or a VPN.

## References

- TryHackMe room page (as configured in the lab)
- Port scanner documentation in this repository
