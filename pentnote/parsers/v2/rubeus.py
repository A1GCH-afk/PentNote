"""Rubeus parser."""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Credential, Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser


class RubeusParser(AbstractParser):
    """Parse Rubeus Kerberos credential material."""

    tool_name = "rubeus"
    aliases = ()
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is Rubeus output."""

        clean = self.clean(content)
        if any(
            token in clean
            for token in (
                "[*] Action:",
                "ServiceName:",
                "EncryptionType:",
                "[+] Ticket successfully imported",
                "doIf",
            )
        ):
            return 0.95
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        """Parse Rubeus output into credentials and findings."""

        clean = self.clean(content)
        credentials: list[Credential] = []
        findings: list[Finding] = []
        partial = False

        for block in _blocks(clean):
            try:
                parsed = _parse_block(block)
            except (IndexError, ValueError):
                partial = True
                continue
            if parsed is None:
                continue

            username = parsed["username"]
            secret = parsed["secret"]
            domain = parsed.get("domain")
            source_host = parsed.get("source_host") or domain or "unknown"
            credentials.append(
                Credential(
                    username=username,
                    secret=secret,
                    secret_type="kerberos",
                    source_host=source_host,
                    domain=domain,
                )
            )

            finding_spec = _finding_spec(block, username)
            if finding_spec is None:
                continue
            title, severity, technique_id, name, tactic = finding_spec
            findings.append(
                _finding(
                    tool=self.tool_name,
                    host=source_host,
                    title=title,
                    severity=severity,
                    technique_id=technique_id,
                    technique_name=name,
                    tactic=tactic,
                    evidence=block.strip(),
                )
            )

        return ParsedResult(
            self.tool_name, partial, [], credentials, findings, [], content
        )


def _blocks(content: str) -> list[str]:
    parts = re.split(r"(?m)(?=^\[\*\] Action:)", content)
    if len(parts) > 1:
        return [part for part in parts if part.strip()]
    return [content]


def _parse_block(block: str) -> dict[str, str] | None:
    username = (
        _field(block, "UserName")
        or _field(block, "SamAccountName")
        or _hash_username(block)
    )
    secret = _field(block, "Ticket") or _field(block, "Hash") or _ticket_blob(block)
    if not username or not secret:
        return None
    domain = (
        _field(block, "DomainName") or _domain_from_dn(block) or _hash_domain(block)
    )
    source_host = _field(block, "ServiceName") or domain
    return {
        "username": username,
        "secret": secret,
        "domain": domain or "",
        "source_host": source_host or "",
    }


def _field(block: str, name: str) -> str | None:
    match = re.search(rf"(?mi)^\s*(?:\[\*\]\s*)?{re.escape(name)}\s*:\s*(.+)$", block)
    if match:
        return match.group(1).strip()
    return None


def _ticket_blob(block: str) -> str | None:
    match = re.search(r"(?s)\b(doIf[A-Za-z0-9+/=\r\n]+)", block)
    if match:
        return re.sub(r"\s+", "", match.group(1))
    return None


def _hash_username(block: str) -> str | None:
    match = re.search(r"\$krb5(?:tgs|asrep)\$[^$]*\$([^@$:\s]+)", block)
    return match.group(1) if match else None


def _hash_domain(block: str) -> str | None:
    match = re.search(r"\$krb5tgs\$[^$]*\$[^$]*\$([^$]+)\$", block)
    if match:
        return match.group(1)
    match = re.search(r"\$krb5asrep\$[^$]*\$[^@:$]+@([^:]+):", block)
    return match.group(1) if match else None


def _domain_from_dn(block: str) -> str | None:
    dn = _field(block, "DistinguishedName")
    if not dn:
        return None
    parts = re.findall(r"DC=([^,]+)", dn, flags=re.IGNORECASE)
    return ".".join(parts) if parts else None


def _finding_spec(
    block: str, username: str
) -> tuple[str, Severity, str, str, str] | None:
    lowered = block.casefold()
    if "ticket successfully imported" in lowered:
        return (
            f"Kerberos Ticket Imported: {username}",
            Severity.CRITICAL,
            "T1550.003",
            "Use Alternate Authentication Material: Pass the Ticket",
            "Defense Evasion",
        )
    if "asreproast" in lowered or "$krb5asrep$" in lowered:
        return (
            f"AS-REP Roastable Account: {username}",
            Severity.HIGH,
            "T1558.004",
            "AS-REP Roasting",
            "Credential Access",
        )
    if "kerberoast" in lowered or "$krb5tgs$" in lowered:
        return (
            f"Kerberoastable Account: {username}",
            Severity.HIGH,
            "T1558.003",
            "Kerberoasting",
            "Credential Access",
        )
    return None


def _finding(
    *,
    tool: str,
    host: str,
    title: str,
    severity: Severity,
    technique_id: str,
    technique_name: str,
    tactic: str,
    evidence: str,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[MitreMatch(technique_id, technique_name, tactic, 1.0, "rule")],
        affected_hosts=[host],
        evidence=evidence,
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash=finding_hash(tool, host, title),
    )
