"""Evil-WinRM transcript parser."""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.core.models import DomainObject
from pentnote.models import Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
OSC_RE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PROMPT_RE = re.compile(r"\*Evil-WinRM\*\s+PS\s+[^>]+>\s*")
DOMAIN_USER_TABLE_RE = re.compile(
    r"User accounts for.*?-{5,}\n(?P<body>.*?)(?:The command completed|$)",
    flags=re.IGNORECASE | re.DOTALL,
)
DOMAIN_GROUP_TABLE_RE = re.compile(
    r"Group Accounts for.*?-{5,}\n(?P<body>.*?)(?:The command completed|$)",
    flags=re.IGNORECASE | re.DOTALL,
)
DANGEROUS_PRIVILEGES = {
    "SeBackupPrivilege",
    "SeDebugPrivilege",
    "SeEnableDelegationPrivilege",
    "SeImpersonatePrivilege",
    "SeLoadDriverPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
}


class EvilWinRMParser(AbstractParser):
    """Parse Evil-WinRM shell transcripts without universal-parser noise."""

    tool_name = "evil-winrm"
    aliases = ("evilwinrm",)
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        clean = _clean_transcript(content).casefold()
        if "evil-winrm shell" in clean or "*evil-winrm*" in clean:
            return 0.95
        if "evil-winrm" in clean and "ps " in clean:
            return 0.85
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        clean = _clean_transcript(content)
        host = _target_host(clean)
        findings: list[Finding] = []
        domain_objects: list[DomainObject] = []

        if "Info: Establishing connection to remote endpoint" in clean:
            findings.append(
                _finding(
                    title="Evil-WinRM Session Established",
                    severity=Severity.INFO,
                    host=host,
                    evidence=_line_containing(clean, "Establishing connection"),
                    technique_id="T1021.006",
                    technique_name="Remote Services: Windows Remote Management",
                    tactic="Lateral Movement",
                )
            )

        users = _domain_users(clean)
        if users:
            domain_objects.extend(
                DomainObject(
                    name=user,
                    object_type="user",
                    domain=_domain(clean),
                    properties={"source": self.tool_name},
                    paths=[],
                )
                for user in users
            )
            findings.append(
                _finding(
                    title=f"Domain Users Enumerated ({len(users)})",
                    severity=Severity.LOW,
                    host=host,
                    evidence=", ".join(users),
                    technique_id="T1087.002",
                    technique_name="Account Discovery: Domain Account",
                    tactic="Discovery",
                )
            )

        groups = _domain_groups(clean)
        if groups:
            domain_objects.extend(
                DomainObject(
                    name=group,
                    object_type="group",
                    domain=_domain(clean),
                    properties={"source": self.tool_name},
                    paths=[],
                )
                for group in groups
            )
            findings.append(
                _finding(
                    title=f"Domain Groups Enumerated ({len(groups)})",
                    severity=Severity.LOW,
                    host=host,
                    evidence=", ".join(groups),
                    technique_id="T1069.002",
                    technique_name="Permission Groups Discovery: Domain Groups",
                    tactic="Discovery",
                )
            )

        current_user = _current_user(clean)
        if current_user:
            domain_objects.append(
                DomainObject(
                    name=current_user.split("\\")[-1],
                    object_type="user",
                    domain=(
                        current_user.split("\\", 1)[0] if "\\" in current_user else ""
                    ),
                    properties={"source": self.tool_name, "session_user": True},
                    paths=[],
                )
            )

        if "BUILTIN\\Administrators" in clean:
            findings.append(
                _finding(
                    title="WinRM Session Has Local Administrator Rights",
                    severity=Severity.HIGH,
                    host=host,
                    evidence=_section(
                        clean, "GROUP INFORMATION", "PRIVILEGES INFORMATION"
                    ),
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                    tactic="Defense Evasion",
                )
            )

        privileges = _enabled_dangerous_privileges(clean)
        if privileges:
            findings.append(
                _finding(
                    title=f"Dangerous Windows Privileges Enabled ({len(privileges)})",
                    severity=Severity.HIGH,
                    host=host,
                    evidence=", ".join(privileges),
                    technique_id="T1134",
                    technique_name="Access Token Manipulation",
                    tactic="Privilege Escalation",
                    next_steps=[
                        "Review enabled privileges for local privilege escalation paths.",
                        "Check SeBackupPrivilege, SeDebugPrivilege, and SeImpersonatePrivilege abuse options.",
                    ],
                )
            )

        detailed_user = _detailed_domain_user(clean)
        if detailed_user:
            findings.append(
                _finding(
                    title=f"Domain User Details Enumerated: {detailed_user}",
                    severity=Severity.INFO,
                    host=host,
                    evidence=_section(
                        clean,
                        f"User name                    {detailed_user}",
                        "The command completed",
                    ),
                    technique_id="T1087.002",
                    technique_name="Account Discovery: Domain Account",
                    tactic="Discovery",
                )
            )

        return ParsedResult(
            self.tool_name,
            partial=False,
            hosts=[],
            credentials=[],
            findings=_dedupe(findings),
            domain_objects=_dedupe_domain_objects(domain_objects),
            raw_text=clean,
        )


def _clean_transcript(content: str) -> str:
    clean = OSC_RE.sub("", content)
    clean = ANSI_RE.sub("", clean)
    clean = CONTROL_RE.sub("", clean)
    clean = clean.replace("\r\n", "\n").replace("\r", "\n")
    clean = clean.replace("\x1b[1G", "")
    clean = PROMPT_RE.sub(lambda match: f"\n{match.group(0)}", clean)
    return "\n".join(line.rstrip() for line in clean.splitlines() if line.strip())


def _target_host(content: str) -> str:
    return "evil-winrm"


def _domain(content: str) -> str:
    match = re.search(r"(?im)^([a-z0-9_.-]+)\\[a-z0-9_.-]+\s+S-\d", content)
    return match.group(1) if match else ""


def _current_user(content: str) -> str | None:
    match = re.search(r"(?im)^([a-z0-9_.-]+\\[a-z0-9_.-]+)\s+S-\d", content)
    return match.group(1) if match else None


def _domain_users(content: str) -> list[str]:
    match = DOMAIN_USER_TABLE_RE.search(content)
    if not match:
        return []
    return _table_names(match.group("body"))


def _domain_groups(content: str) -> list[str]:
    match = DOMAIN_GROUP_TABLE_RE.search(content)
    if not match:
        return []
    return [name.lstrip("*") for name in _table_names(match.group("body"))]


def _table_names(value: str) -> list[str]:
    names: list[str] = []
    for line in value.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        for name in re.split(r"\s{2,}", stripped):
            cleaned = name.strip().strip("*")
            if cleaned and not cleaned.casefold().startswith("the command"):
                names.append(cleaned)
    return _unique(names)


def _enabled_dangerous_privileges(content: str) -> list[str]:
    found: list[str] = []
    for privilege in DANGEROUS_PRIVILEGES:
        pattern = rf"(?im)^{re.escape(privilege)}\s+.*\sEnabled\s*$"
        if re.search(pattern, content):
            found.append(privilege)
    return sorted(found)


def _detailed_domain_user(content: str) -> str | None:
    for match in re.finditer(r"(?im)^User name\s{2,}([a-z0-9_.-]+)\s*$", content):
        value = match.group(1)
        if value.casefold() != "sid":
            return value
    return None


def _line_containing(content: str, needle: str) -> str:
    for line in content.splitlines():
        if needle in line:
            return line.strip()
    return needle


def _section(content: str, start: str, end: str) -> str:
    start_index = content.find(start)
    if start_index == -1:
        return ""
    end_index = content.find(end, start_index + len(start))
    if end_index == -1:
        return content[start_index:].strip()
    return content[start_index:end_index].strip()


def _finding(
    *,
    title: str,
    severity: Severity,
    host: str,
    evidence: str,
    technique_id: str,
    technique_name: str,
    tactic: str,
    next_steps: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[
            MitreMatch(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                confidence=0.85,
                source="evil-winrm",
            )
        ],
        affected_hosts=[host] if host else [],
        evidence=evidence,
        next_steps=next_steps
        or ["Correlate this Evil-WinRM observation with the active objective."],
        defenses=[],
        chain_member=None,
        hash=finding_hash("evil-winrm", host, title),
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result: list[Finding] = []
    for finding in findings:
        if finding.hash in seen:
            continue
        seen.add(finding.hash)
        result.append(finding)
    return result


def _dedupe_domain_objects(objects: list[DomainObject]) -> list[DomainObject]:
    seen: set[tuple[str, str, str]] = set()
    result: list[DomainObject] = []
    for obj in objects:
        key = (obj.object_type, obj.domain.casefold(), obj.name.casefold())
        if key in seen:
            continue
        seen.add(key)
        result.append(obj)
    return result


def _unique(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
