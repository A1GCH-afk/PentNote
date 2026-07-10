"""Evil-WinRM transcript parser."""

from __future__ import annotations

import re
from typing import Any

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
# `net user <name>` and `net group <name>` detail blocks begin with a left-column
# field label. The value column starts after 2+ spaces (a group name such as
# "Domain Admins" keeps its internal single spaces).
NET_USER_START_RE = re.compile(r"(?i)^User name\s{2,}(?P<name>\S.*?)\s*$")
NET_GROUP_START_RE = re.compile(r"(?i)^Group name\s{2,}(?P<name>\S.*?)\s*$")
# Membership values are '*'-prefixed and may wrap onto indented continuation
# lines; net.exe truncates long names to the fixed column width.
MEMBERSHIP_FIELDS = {"local group memberships", "global group memberships"}
NAME_FIELDS = {"user name", "group name"}
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
        domain = _domain(clean)
        findings: list[Finding] = []
        domain_objects: list[DomainObject] = []
        detailed_users = _detailed_net_users(clean)
        detailed_groups = _detailed_net_groups(clean)

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
        listed_users = {user.casefold() for user in users}
        if users:
            domain_objects.extend(
                DomainObject(
                    name=user,
                    object_type="user",
                    domain=domain,
                    properties=_object_properties(
                        self.tool_name, detailed_users.get(user.casefold())
                    ),
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
        # A `net user <name>` run without a preceding `net user` listing still
        # deserves its own populated note.
        for key, (display_name, props) in detailed_users.items():
            if key in listed_users:
                continue
            domain_objects.append(
                DomainObject(
                    name=display_name,
                    object_type="user",
                    domain=domain,
                    properties=_object_properties(
                        self.tool_name, (display_name, props)
                    ),
                    paths=[],
                )
            )

        groups = _domain_groups(clean)
        listed_groups = {group.casefold() for group in groups}
        if groups:
            domain_objects.extend(
                DomainObject(
                    name=group,
                    object_type="group",
                    domain=domain,
                    properties=_object_properties(
                        self.tool_name, detailed_groups.get(group.casefold())
                    ),
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
        for key, (display_name, props) in detailed_groups.items():
            if key in listed_groups:
                continue
            domain_objects.append(
                DomainObject(
                    name=display_name,
                    object_type="group",
                    domain=domain,
                    properties=_object_properties(
                        self.tool_name, (display_name, props)
                    ),
                    paths=[],
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


def _detailed_net_users(content: str) -> dict[str, tuple[str, dict[str, Any]]]:
    """Map casefolded username -> (display name, parsed `net user <name>` fields)."""

    result: dict[str, tuple[str, dict[str, Any]]] = {}
    for name, block in _iter_detail_blocks(content, NET_USER_START_RE):
        if name.casefold() == "sid":  # whoami /all header, not a net user block
            continue
        props = _parse_net_user_props(block)
        if props:
            result[name.casefold()] = (name, props)
    return result


def _detailed_net_groups(content: str) -> dict[str, tuple[str, dict[str, Any]]]:
    """Map casefolded group name -> (display name, parsed `net group <name>` fields)."""

    result: dict[str, tuple[str, dict[str, Any]]] = {}
    for name, block in _iter_detail_blocks(content, NET_GROUP_START_RE):
        props = _parse_net_group_props(block)
        if props:
            result[name.casefold()] = (name, props)
    return result


def _iter_detail_blocks(
    content: str, start_re: re.Pattern[str]
) -> list[tuple[str, list[str]]]:
    """Yield (name, body-lines) for each detail block opened by ``start_re``.

    A block runs from just after its header line until the trailing ``The
    command completed`` line, the next detail header, or the next shell prompt.
    """

    lines = content.splitlines()
    blocks: list[tuple[str, list[str]]] = []
    index = 0
    total = len(lines)
    while index < total:
        match = start_re.match(lines[index])
        if not match:
            index += 1
            continue
        name = match.group("name").strip()
        body: list[str] = []
        cursor = index + 1
        while cursor < total:
            line = lines[cursor]
            if _is_block_terminator(line):
                break
            body.append(line)
            cursor += 1
        blocks.append((name, body))
        index = cursor
    return blocks


def _is_block_terminator(line: str) -> bool:
    stripped = line.lstrip()
    return (
        stripped.casefold().startswith("the command completed")
        or stripped.startswith("*Evil-WinRM*")
        or bool(NET_USER_START_RE.match(line))
        or bool(NET_GROUP_START_RE.match(line))
    )


def _parse_net_user_props(block: list[str]) -> dict[str, Any]:
    """Parse ``net user <name>`` field/value lines into note properties."""

    props: dict[str, Any] = {}
    current: str | None = None
    for line in block:
        if not line.strip():
            continue
        if line[0].isspace():  # indented continuation of a membership list
            if current and current.casefold() in MEMBERSHIP_FIELDS:
                props.setdefault(current, []).extend(_split_star(line))
            continue
        field, value = _split_field(line)
        current = field
        low = field.casefold()
        if low in NAME_FIELDS:
            continue
        if low in MEMBERSHIP_FIELDS:
            props.setdefault(field, [])
            if value:
                props[field].extend(_split_star(value))
        elif value:
            props[field] = value
    return _finalize_props(props)


def _parse_net_group_props(block: list[str]) -> dict[str, Any]:
    """Parse ``net group <name>`` output (comment plus member roster)."""

    props: dict[str, Any] = {}
    members: list[str] = []
    in_members = False
    for line in block:
        stripped = line.strip()
        if not stripped:
            continue
        if set(stripped) <= {"-"}:  # ----- separator above the member roster
            continue
        if stripped.casefold() == "members":
            in_members = True
            continue
        if in_members:
            members.extend(_split_columns(stripped))
            continue
        field, value = _split_field(line)
        if field.casefold() in NAME_FIELDS:
            continue
        if value:
            props[field] = value
    unique_members = _unique([member for member in members if member])
    if unique_members:
        props["Members"] = unique_members
    return props


def _finalize_props(props: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field, value in props.items():
        if isinstance(value, list):
            deduped = _unique([item for item in value if item])
            if deduped:
                result[field] = deduped
        elif value:
            result[field] = value
    return result


def _object_properties(
    tool: str, detail: tuple[str, dict[str, Any]] | None
) -> dict[str, Any]:
    props: dict[str, Any] = {"source": tool}
    if detail:
        props.update(detail[1])
    return props


def _split_field(line: str) -> tuple[str, str]:
    parts = re.split(r"\s{2,}", line.strip(), maxsplit=1)
    field = parts[0].strip()
    value = parts[1].strip() if len(parts) > 1 else ""
    return field, value


def _split_star(text: str) -> list[str]:
    return [part.strip() for part in text.split("*") if part.strip()]


def _split_columns(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"\s{2,}", text.strip()) if part.strip()]


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
