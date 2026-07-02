"""Seatbelt parser for Windows post-exploitation checks."""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.models import (
    Credential,
    Finding,
    Host,
    MitreMatch,
    ParsedResult,
    Severity,
)
from pentnote.parsers.base import AbstractParser

STRONG_SIGNALS = (
    "Seatbelt",
    "=== ",
    "OSInfo",
    "WindowsDefender",
    "UACPolicies",
    "PowerShellHistory",
    "CredGuard",
)


class SeatbeltParser(AbstractParser):
    """Parse common Seatbelt security configuration output."""

    tool_name = "seatbelt"
    aliases = ("seatbelt-exe",)
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        clean = self.clean(content)
        hits = sum(
            1 for signal in STRONG_SIGNALS if signal.casefold() in clean.casefold()
        )
        if "seatbelt" in clean.casefold() and hits >= 2:
            return 0.95
        if hits >= 3:
            return 0.9
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        clean = self.clean(content)
        sections = _sections(clean)
        host = _host(sections.get("OSInfo", ""))
        host_id = host.ip if host else "seatbelt"
        findings: list[Finding] = []
        credentials: list[Credential] = []

        defender = sections.get("WindowsDefender", "")
        if "DisableRealtimeMonitoring" in defender and re.search(
            r"DisableRealtimeMonitoring\s*:\s*True", defender, re.I
        ):
            findings.append(
                _finding(
                    "Windows Defender Real-time Protection Disabled",
                    Severity.HIGH,
                    host_id,
                    defender,
                    "T1562.001",
                    "Impair Defenses: Disable or Modify Tools",
                    "Defense Evasion",
                )
            )

        uac = sections.get("UACPolicies", "")
        if re.search(r"EnableLUA\s*:\s*0", uac, re.I) or re.search(
            r"ConsentPromptBehaviorAdmin\s*:\s*0", uac, re.I
        ):
            findings.append(
                _finding(
                    "UAC Disabled or Bypassable",
                    Severity.HIGH,
                    host_id,
                    uac,
                    "T1548.002",
                    "Abuse Elevation Control Mechanism: Bypass User Account Control",
                    "Privilege Escalation",
                )
            )

        credguard = sections.get("CredGuard", "")
        if re.search(r"IsRunning\s*:\s*False", credguard, re.I):
            findings.append(
                _finding(
                    "Credential Guard Not Running",
                    Severity.HIGH,
                    host_id,
                    credguard,
                    "T1003.001",
                    "OS Credential Dumping: LSASS Memory",
                    "Credential Access",
                )
            )

        history = sections.get("PowerShellHistory", "")
        if re.search(r"(?i)(password|passwd|secret|token)\s*[:=]\s*\S+", history):
            findings.append(
                _finding(
                    "Credentials in PowerShell History",
                    Severity.CRITICAL,
                    host_id,
                    history,
                    "T1552.001",
                    "Unsecured Credentials: Credentials In Files",
                    "Credential Access",
                )
            )

        laps = sections.get("LAPSSettings", "")
        laps_installed = re.search(
            r"(?<!No\s)AdmPwd\.dll|LAPS\s*:\s*(True|Installed)", laps, re.I
        )
        if "LAPSSettings" in clean and not laps_installed:
            findings.append(
                _finding(
                    "LAPS Not Installed",
                    Severity.MEDIUM,
                    host_id,
                    laps or "LAPSSettings",
                    "T1110.001",
                    "Brute Force: Password Guessing",
                    "Credential Access",
                )
            )

        autologon = sections.get("AutoLogon", "") or clean
        username = _value(autologon, "DefaultUserName")
        password = _value(autologon, "DefaultPassword")
        if username and password:
            credentials.append(
                Credential(
                    username=username,
                    secret=password,
                    secret_type="plaintext",
                    source_host=host_id,
                )
            )
            findings.append(
                _finding(
                    "AutoLogon Credentials Found",
                    Severity.CRITICAL,
                    host_id,
                    autologon,
                    "T1552.002",
                    "Unsecured Credentials: Credentials in Registry",
                    "Credential Access",
                    next_steps=[
                        "Use autologon credentials immediately.",
                        f"cme smb {host_id} -u {username} -p {password}",
                    ],
                )
            )

        return ParsedResult(
            self.tool_name,
            partial=False,
            hosts=[host] if host else [],
            credentials=credentials,
            findings=_dedupe(findings),
            domain_objects=[],
            raw_text=clean,
        )


def _sections(content: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current = ""
    for line in content.splitlines():
        match = re.match(r"\s*={3,}\s*(.+?)\s*={3,}\s*$", line)
        if match:
            current = match.group(1).strip()
            sections.setdefault(current, [])
            continue
        if current:
            sections.setdefault(current, []).append(line)
    return {key: "\n".join(lines).strip() for key, lines in sections.items()}


def _host(section: str) -> Host | None:
    if not section:
        return None
    os_version = _value(section, "OSVersion")
    arch = _value(section, "Architecture")
    if not os_version and not arch:
        return None
    os_label = " ".join(value for value in (os_version, arch) if value)
    return Host(ip="seatbelt-host", hostname=None, os=os_label, ports=[], tags=[])


def _value(content: str, key: str) -> str | None:
    match = re.search(rf"(?im)^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", content)
    return match.group(1).strip() if match else None


def _finding(
    title: str,
    severity: Severity,
    host: str,
    evidence: str,
    technique_id: str,
    technique_name: str,
    tactic: str,
    *,
    next_steps: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[
            MitreMatch(technique_id, technique_name, tactic, 0.9, "seatbelt")
        ],
        affected_hosts=[host] if host else [],
        evidence=evidence,
        next_steps=next_steps
        or ["Validate the Seatbelt finding on the affected host."],
        defenses=[],
        chain_member=None,
        hash=finding_hash("seatbelt", host, title),
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
