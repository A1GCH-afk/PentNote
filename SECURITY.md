# Security Policy

## Authorized Use Only

PentNote is intended **exclusively for authorized security assessments**, including:
- Penetration tests with written client authorization (Statement of Work, ROE).
- Capture-the-flag (CTF) competitions on authorized infrastructure.
- Personal lab environments you own or have explicit permission to test.

Using PentNote against systems you do not own or do not have written authorization to test
is illegal in most jurisdictions. The authors accept no responsibility for unauthorized use.

## Data Handling

PentNote stores all data **locally** on the user's filesystem. It does not:
- Transmit engagement data to remote servers.
- Phone home or collect telemetry.
- Share parsed output with third parties.

Optional integrations (e.g., Ollama for local LLM redaction) run entirely on the user's machine.

## Supported Versions

Only the latest minor release receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Reporting a Vulnerability

If you discover a security issue in PentNote itself (not in the tools it
parses), please report it privately using GitHub's built-in reporting
feature — do not open a public issue.

1. Go to the [Security tab](https://github.com/A1GCH-afk/PentNote/security)
   of this repository
2. Click **"Report a vulnerability"**
3. Fill out the advisory form with as much detail as possible
   (affected version, reproduction steps, impact)

This creates a private draft security advisory visible only to the
maintainer, with built-in tracking and CVE-assignment support if
needed. You will receive a response as described in the timeline below.

Please include:
- A clear description of the issue.
- Steps to reproduce.
- The version affected.
- The potential impact.

## Disclosure Timeline

- Acknowledgement within 7 days.
- Triage and assessment within 14 days.
- Fix or mitigation within 90 days for high-severity issues.
- Coordinated public disclosure after a fix is released.

We follow responsible disclosure principles and ask reporters to do the same.

## Out of Scope

The following are NOT considered security vulnerabilities in PentNote:
- Vulnerabilities in tools whose output PentNote parses (report those to the respective tool maintainers).
- Issues that require the attacker to already have write access to the user's filesystem.
- Issues in third-party Python dependencies (report those upstream; PentNote will update when a fixed version is available).
