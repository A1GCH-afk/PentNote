"""Mimikatz parser."""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Credential, Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser


class MimikatzParser(AbstractParser):
    """Parse Mimikatz credential output."""

    tool_name = "mimikatz"
    aliases = ()
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is Mimikatz output."""

        lowered = self.clean(content).casefold()
        if any(
            token in lowered
            for token in (
                "mimikatz",
                "sekurlsa::",
                "lsadump::",
                "* username :",
                "* ntlm     :",
                "* password :",
                "authentication id",
            )
        ):
            return 0.95
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        """Parse Mimikatz output into credentials and findings."""

        clean = self.clean(content)
        source_host = _field(clean, "Logon Server") or "unknown"
        credentials: list[Credential] = []
        findings: list[Finding] = []
        partial = False

        for block in _credential_blocks(clean):
            try:
                parsed = _parse_credential_block(block)
            except (IndexError, ValueError):
                partial = True
                continue
            if parsed is None:
                continue

            username = parsed["username"]
            domain = parsed["domain"]
            for secret_type, secret in parsed["secrets"]:
                credentials.append(
                    Credential(
                        username=username,
                        secret=secret,
                        secret_type=secret_type,
                        source_host=source_host,
                        domain=domain,
                    )
                )
                title = (
                    f"NTLM Hash Dumped: {domain}\\{username}"
                    if secret_type == "ntlm"
                    else f"Plaintext Credential: {domain}\\{username}"
                )
                findings.append(
                    _finding(
                        tool=self.tool_name,
                        host=source_host,
                        title=title,
                        evidence=block.strip(),
                    )
                )

        return ParsedResult(
            self.tool_name, partial, [], credentials, findings, [], content
        )


def _credential_blocks(content: str) -> list[str]:
    matches = list(re.finditer(r"(?mi)^\s*\*\s*Username\s*:", content))
    blocks: list[str] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(content)
        blocks.append(content[start:end])
    return blocks


def _parse_credential_block(block: str) -> dict[str, object] | None:
    username = _star_field(block, "Username")
    domain = _star_field(block, "Domain") or ""
    if not username:
        return None

    secrets: list[tuple[str, str]] = []
    ntlm = _star_field(block, "NTLM")
    if ntlm and _valid_secret(ntlm):
        secrets.append(("ntlm", ntlm))
    password = _star_field(block, "Password")
    if password and _valid_secret(password):
        secrets.append(("plaintext", password))
    ticket = _star_field(block, "Ticket")
    if ticket and _valid_secret(ticket):
        secrets.append(("kerberos", ticket))

    if not secrets:
        return None
    return {"username": username, "domain": domain, "secrets": secrets}


def _field(content: str, name: str) -> str | None:
    match = re.search(rf"(?mi)^\s*{re.escape(name)}\s*:\s*(.+)$", content)
    return match.group(1).strip() if match else None


def _star_field(content: str, name: str) -> str | None:
    match = re.search(rf"(?mi)^\s*\*\s*{re.escape(name)}\s*:\s*(.+)$", content)
    return match.group(1).strip() if match else None


def _valid_secret(secret: str) -> bool:
    return bool(secret.strip()) and secret.strip().casefold() != "(null)"


def _finding(*, tool: str, host: str, title: str, evidence: str) -> Finding:
    return Finding(
        title=title,
        severity=Severity.CRITICAL,
        mitre_matches=[
            MitreMatch(
                "T1003.001",
                "OS Credential Dumping: LSASS Memory",
                "Credential Access",
                1.0,
                "rule",
            )
        ],
        affected_hosts=[host],
        evidence=evidence,
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash=finding_hash(tool, host, title),
    )
