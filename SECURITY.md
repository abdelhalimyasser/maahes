# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.
Report them privately:

- **Preferred:** email the maintainer — **abdelhalimyasser88@gmail.com**
  with the subject prefix `[maahes-security]`.
- Optionally, once an email is confirmed, a GitHub Security Advisory
  (private) can be opened for coordination.

Include, when available:

1. The affected version(s) and module (`Password` / `Cors` /
   `SecurityHeaders`).
2. A minimal reproduction (config + inputs).
3. Impact assessment (what an attacker gains, and under what threat
   model — see [docs/threat-model.md](docs/threat-model.md)).

## Handling

- Confirmation of receipt within **3 business days**.
- A fix is prioritized based on severity and published as a patch
  release; the advisory is disclosed after the fix ships (or sooner if
  the issue is already public).

## Scope

In scope: the code in this repository and its published npm artifacts.
Out of scope: applications built *with* Maahes (report those to their
owners), and misconfiguration (documented in
[docs/security.md](docs/security.md)).

## Known-good practices for reporters

- Do not include live secrets, passwords or pepper material in reports.
- Errored inputs are fine — Maahes never logs values, but double-check
  your own captures before pasting.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | ✅ security fixes |
| < 1.0 | ❌ (pre-release, use latest 1.x) |