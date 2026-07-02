"""enum4linux-ng parser."""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.models import DomainObject, Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser


class Enum4linuxParser(AbstractParser):
    """Parse enum4linux-ng SMB enumeration output."""

    tool_name = "enum4linux"
    aliases = ("enum4linux-ng",)
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is enum4linux-ng output."""

        lowered = self.clean(content).casefold()
        if any(
            token in lowered
            for token in (
                "enum4linux",
                "enum4linux-ng",
                "[+] server",
                "| users via rpc |",
                "| groups via rpc |",
                "| shares via smb |",
                "index: 0x",
            )
        ):
            return 0.95
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        """Parse enum4linux-ng output into domain objects and findings."""

        clean = self.clean(content)
        domain = _domain(clean)
        domain_objects: list[DomainObject] = []
        findings: list[Finding] = []
        partial = False

        try:
            domain_objects.extend(_users(clean, domain))
            domain_objects.extend(_groups(clean, domain))
            shares = _shares(clean, domain)
            domain_objects.extend(shares)
        except (IndexError, ValueError):
            partial = True
            shares = []

        shares_section = _section(clean, "Shares via SMB")
        if shares and shares_section:
            findings.append(
                _finding(
                    tool=self.tool_name,
                    host=domain,
                    title="Anonymous SMB Access Allowed",
                    severity=Severity.HIGH,
                    technique_id="T1135",
                    technique_name="Network Share Discovery",
                    tactic="Discovery",
                    evidence=shares_section,
                )
            )

        null_section = _null_session_section(clean)
        if null_section:
            findings.append(
                _finding(
                    tool=self.tool_name,
                    host=domain,
                    title="Null Session Allowed",
                    severity=Severity.HIGH,
                    technique_id="T1069.002",
                    technique_name="Permission Groups Discovery: Domain Groups",
                    tactic="Discovery",
                    evidence=null_section,
                )
            )

        policy_section = _section(clean, "Password Policy")
        if policy_section and _weak_policy(policy_section):
            findings.append(
                _finding(
                    tool=self.tool_name,
                    host=domain,
                    title="Weak Password Policy Detected",
                    severity=Severity.MEDIUM,
                    technique_id="T1110.001",
                    technique_name="Password Guessing",
                    tactic="Credential Access",
                    evidence=policy_section,
                )
            )

        return ParsedResult(
            self.tool_name,
            partial,
            [],
            [],
            findings,
            domain_objects,
            content,
        )


def _domain(content: str) -> str:
    for pattern in (
        r"(?mi)^\s*(?:Workgroup|Domain)\s*:\s*(\S+)",
        r"(?mi)^\s*\[\+\]\s*(?:Workgroup|Domain)\s*:\s*(\S+)",
    ):
        match = re.search(pattern, content)
        if match:
            return match.group(1)
    return "unknown"


def _users(content: str, domain: str) -> list[DomainObject]:
    section = _section(content, "Users via RPC")
    if not section:
        return []
    users: list[DomainObject] = []
    for match in re.finditer(
        r"index:\s*0x[0-9a-f]+\s+RID:\s*(0x[0-9a-f]+).*?Account:\s*(\S+)",
        section,
        flags=re.IGNORECASE,
    ):
        users.append(
            DomainObject(
                name=match.group(2),
                object_type="user",
                domain=domain,
                properties={"rid": match.group(1), "source": "enum4linux"},
                paths=[],
            )
        )
    return users


def _groups(content: str, domain: str) -> list[DomainObject]:
    section = _section(content, "Groups via RPC")
    if not section:
        return []
    groups: list[DomainObject] = []
    for line in section.splitlines():
        match = re.search(r"(?:Group|group):\s*(.+?)(?:\s+RID:|$)", line)
        if match:
            groups.append(
                DomainObject(
                    name=match.group(1).strip(),
                    object_type="group",
                    domain=domain,
                    properties={"source": "enum4linux"},
                    paths=[],
                )
            )
    return groups


def _shares(content: str, domain: str) -> list[DomainObject]:
    section = _section(content, "Shares via SMB")
    if not section:
        return []
    shares: list[DomainObject] = []
    for line in section.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith(("[", "=", "|"))
            or stripped.casefold().startswith("share")
        ):
            continue
        match = re.match(r"^(\S+)\s+(\S+)\s*(.*)$", stripped)
        if not match:
            continue
        share_type = match.group(2)
        if share_type.casefold() not in {"disk", "ipc", "printer"}:
            continue
        shares.append(
            DomainObject(
                name=match.group(1),
                object_type="share",
                domain=domain,
                properties={
                    "type": share_type,
                    "comment": match.group(3).strip(),
                    "source": "enum4linux",
                },
                paths=[],
            )
        )
    return shares


def _section(content: str, title: str) -> str:
    match = re.search(
        rf"(?is)\|\s*{re.escape(title)}[^\n]*\|(?P<body>.*?)(?=\n\s*=+\s*\n\s*\||\Z)",
        content,
    )
    return match.group(0).strip() if match else ""


def _null_session_section(content: str) -> str:
    lines = [
        line
        for line in content.splitlines()
        if "null session" in line.casefold() or "anonymous login" in line.casefold()
    ]
    return "\n".join(lines)


def _weak_policy(section: str) -> bool:
    lowered = section.casefold()
    return "minimum password length: 0" in lowered or "lockout threshold: 0" in lowered


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
