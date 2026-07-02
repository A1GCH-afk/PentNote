"""PowerView and SharpView parser."""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.core.models import DomainObject
from pentnote.models import Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

STRONG_SIGNALS = (
    "PowerView",
    "SharpView",
    "PowerSharpPack",
    "Get-NetUser",
    "Get-NetGroup",
    "Get-NetComputer",
    "Get-DomainUser",
    "Get-DomainGroup",
    "Invoke-ACLScanner",
    "Find-LocalAdminAccess",
)


class PowerViewParser(AbstractParser):
    """Parse common PowerView/SharpView enumeration output."""

    tool_name = "powerview"
    aliases = ("pv", "powerview-ps1", "sharpview", "powersharppack")
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        clean = self.clean(content)
        hits = sum(
            1 for signal in STRONG_SIGNALS if signal.casefold() in clean.casefold()
        )
        if hits >= 2:
            return 0.95
        if hits == 1:
            return 0.86
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        clean = self.clean(content)
        domain_objects = _domain_objects(clean)
        findings = [
            *_local_admin_findings(clean),
            *_dangerous_acl_findings(clean),
            *_kerberoastable_findings(clean),
            *_unconstrained_delegation_findings(clean),
        ]
        return ParsedResult(
            self.tool_name,
            partial=False,
            hosts=[],
            credentials=[],
            findings=_dedupe_findings(findings),
            domain_objects=_dedupe_objects(domain_objects),
            raw_text=clean,
        )


def _domain_objects(content: str) -> list[DomainObject]:
    objects: list[DomainObject] = []
    users = _table_users(content)
    users.extend(_property_users(content))
    for user in users:
        objects.append(
            DomainObject(
                name=user["samaccountname"],
                object_type="user",
                domain=_domain_from_dn(user.get("distinguishedname", "")),
                properties=user,
                paths=[],
            )
        )
    for group in _groups(content):
        objects.append(
            DomainObject(
                name=group["name"],
                object_type="group",
                domain="",
                properties=group,
                paths=[],
            )
        )
    return objects


def _table_users(content: str) -> list[dict[str, str]]:
    users: list[dict[str, str]] = []
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if (
            "samaccountname" not in line.casefold()
            or "description" not in line.casefold()
        ):
            continue
        for row in lines[index + 2 :]:
            stripped = row.strip()
            if not stripped or stripped.startswith("PS ") or stripped.startswith("---"):
                continue
            if stripped.casefold().startswith(("get-", "find-", "invoke-")):
                break
            parts = re.split(r"\s{2,}", stripped, maxsplit=1)
            if parts and re.match(r"^[\w.$-]+$", parts[0]):
                users.append(
                    {
                        "samaccountname": parts[0],
                        "description": parts[1] if len(parts) > 1 else "",
                    }
                )
    return users


def _property_users(content: str) -> list[dict[str, str]]:
    users: list[dict[str, str]] = []
    blocks = re.split(r"\n\s*\n", content)
    for block in blocks:
        if "samaccountname" not in block.casefold():
            continue
        props = _properties(block)
        name = props.get("samaccountname")
        if name:
            users.append(props)
    return users


def _groups(content: str) -> list[dict[str, str]]:
    groups: list[dict[str, str]] = []
    for block in re.split(r"\n\s*\n", content):
        lower = block.casefold()
        if (
            "get-netgroup" not in lower
            and "get-domaingroup" not in lower
            and "member_count" not in lower
        ):
            continue
        props = _properties(block)
        name = props.get("name") or props.get("samaccountname")
        if name:
            groups.append({"name": name, "member_count": props.get("member_count", "")})
    return groups


def _properties(block: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().casefold().replace(" ", "_")
        props[key] = value.strip()
    return props


def _local_admin_findings(content: str) -> list[Finding]:
    findings: list[Finding] = []
    in_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if "Find-LocalAdminAccess" in stripped:
            in_section = True
            continue
        if in_section and stripped.startswith("PS "):
            continue
        if in_section and not stripped:
            continue
        if in_section and re.search(r"\b[A-Z0-9_.-]+\.[A-Z0-9_.-]+\b", stripped, re.I):
            computer = stripped.split()[0]
            findings.append(
                _finding(
                    f"Local Admin Access: {computer}",
                    Severity.CRITICAL,
                    computer,
                    stripped,
                    "T1069.001",
                    "Permission Groups Discovery: Local Groups",
                    "Discovery",
                )
            )
    return findings


def _dangerous_acl_findings(content: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in content.splitlines():
        lower = line.casefold()
        if "invoke-aclscanner" in lower:
            continue
        if any(
            right in lower
            for right in (
                "genericall",
                "genericwrite",
                "writedacl",
                "writeowner",
                "all extended rights",
            )
        ):
            obj = (
                _match_value(
                    line, r"(?:objectdn|objectname|identity)\s*[:=]\s*([^,;]+)"
                )
                or "domain object"
            )
            rights = (
                _match_value(
                    line, r"(?:rights|activedirectoryrights)\s*[:=]\s*([^,;]+)"
                )
                or "dangerous rights"
            )
            findings.append(
                _finding(
                    f"Dangerous ACL: {obj} -> {rights}",
                    Severity.HIGH,
                    "",
                    line.strip(),
                    "T1222",
                    "File and Directory Permissions Modification",
                    "Defense Evasion",
                )
            )
    return findings


def _kerberoastable_findings(content: str) -> list[Finding]:
    findings: list[Finding] = []
    for block in re.split(r"\n\s*\n", content):
        lower = block.casefold()
        if "serviceprincipalname" not in lower:
            continue
        props = _properties(block)
        user = props.get("samaccountname") or _match_value(
            block, r"(?im)^([a-z0-9_.-]+)\s+.+serviceprincipalname"
        )
        if user:
            findings.append(
                _finding(
                    f"Kerberoastable Account: {user}",
                    Severity.HIGH,
                    "",
                    block.strip(),
                    "T1558.003",
                    "Steal or Forge Kerberos Tickets: Kerberoasting",
                    "Credential Access",
                )
            )
    return findings


def _unconstrained_delegation_findings(content: str) -> list[Finding]:
    findings: list[Finding] = []
    for block in re.split(r"\n\s*\n", content):
        lower = block.casefold()
        if "unconstrained" not in lower and "trustedfordelegation" not in lower:
            continue
        if "true" not in lower and "unconstrained" not in lower:
            continue
        props = _properties(block)
        computer = props.get("dnshostname") or props.get("name") or "computer"
        findings.append(
            _finding(
                f"Unconstrained Delegation: {computer}",
                Severity.CRITICAL,
                computer,
                block.strip(),
                "T1558.003",
                "Steal or Forge Kerberos Tickets",
                "Credential Access",
            )
        )
    return findings


def _finding(
    title: str,
    severity: Severity,
    host: str,
    evidence: str,
    technique_id: str,
    technique_name: str,
    tactic: str,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[
            MitreMatch(technique_id, technique_name, tactic, 0.9, "powerview")
        ],
        affected_hosts=[host] if host else [],
        evidence=evidence,
        next_steps=["Validate the PowerView finding and map affected AD objects."],
        defenses=[],
        chain_member=None,
        hash=finding_hash("powerview", host, title),
    )


def _domain_from_dn(value: str) -> str:
    parts = re.findall(r"DC=([^,]+)", value, flags=re.I)
    return ".".join(parts)


def _match_value(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, flags=re.I)
    return match.group(1).strip() if match else None


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result: list[Finding] = []
    for finding in findings:
        if finding.hash in seen:
            continue
        seen.add(finding.hash)
        result.append(finding)
    return result


def _dedupe_objects(objects: list[DomainObject]) -> list[DomainObject]:
    seen: set[tuple[str, str, str]] = set()
    result: list[DomainObject] = []
    for obj in objects:
        key = (obj.object_type, obj.domain.casefold(), obj.name.casefold())
        if key in seen:
            continue
        seen.add(key)
        result.append(obj)
    return result
