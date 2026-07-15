"""smbclient (Samba SMB client) parser.

Handles the two shapes PentNote captures from ``smbclient``:

* ``smbclient -L //host/`` share listings (the ``Sharename/Type/Comment`` table)
* interactive sessions (``smbclient //host/Share`` then ``ls``/``mget``), whose
  captures carry bracketed-paste / prompt-redraw terminal noise.

Without this parser both fall through to the universal fallback, which records
no useful structure for a share table and nothing at all for a short listing.
"""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.models import (
    DomainObject,
    Finding,
    Host,
    MitreMatch,
    ParsedResult,
    Port,
    Severity,
)
from pentnote.parsers.base import AbstractParser

# Interactive captures keep terminal control noise the base cleaner leaves
# behind (its CSI pattern does not cover the ``?`` private-parameter marker
# used by bracketed-paste ``\x1b[?2004h``).
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_OSC_RE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Shares present on every Windows host; the interesting ones are everything else.
_DEFAULT_SHARES = {"admin$", "c$", "ipc$", "netlogon", "sysvol", "print$"}

_SHARE_HEADER_RE = re.compile(r"(?im)^\s*Sharename\s+Type\s+Comment\b")
_SHARE_ROW_RE = re.compile(
    r"^\s*(?P<name>\S+)\s+(?P<type>Disk|IPC|Printer)\b\s*(?P<comment>.*?)\s*$"
)
_FILE_ROW_RE = re.compile(
    r"^\s+(?P<name>.+?)\s+(?P<attr>[DAHNSRO]+)\s+(?P<size>\d+)\s+"
    r"(?P<date>\w{3}\s+\w{3}\s+\d+\s+\d\d:\d\d:\d\d\s+\d{4})\s*$"
)
_TARGET_RE = re.compile(r"//(?P<target>[A-Za-z0-9._-]+)/(?P<share>[^/\s]*)")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class SmbClientParser(AbstractParser):
    """Parse smbclient share listings and directory listings."""

    tool_name = "smbclient"
    aliases = ()
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is smbclient output."""

        lowered = _clean(content).casefold()
        if re.search(r"(?m)^#\s*command:\s*smbclient\b", lowered):
            return 0.97
        signals = 0
        if "smb: \\>" in lowered:
            signals += 1
        if "reconnecting with smb1" in lowered or "do_connect:" in lowered:
            signals += 1
        if re.search(r"sharename\s+type\s+comment", lowered):
            signals += 1
        if re.search(r"blocks of size \d+", lowered):
            signals += 1
        if signals >= 2:
            return 0.9
        if signals == 1:
            return 0.55
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        """Parse smbclient output into hosts, shares, and findings."""

        clean = _clean(content)
        target, share = _target_and_share(clean)
        shares = _parse_shares(clean)
        files = _parse_files(clean)

        hosts: list[Host] = []
        if target and _IPV4_RE.match(target):
            hosts.append(
                Host(
                    ip=target,
                    ports=[
                        Port(
                            number=445,
                            protocol="tcp",
                            service="microsoft-ds",
                            state="open",
                        )
                    ],
                )
            )

        domain_objects = [
            DomainObject(
                name=name,
                object_type="share",
                properties={
                    "type": share_type,
                    "comment": comment,
                    "default": name.casefold() in _DEFAULT_SHARES,
                    "source": self.tool_name,
                },
            )
            for name, share_type, comment in shares
        ]

        findings: list[Finding] = []
        if shares:
            non_default = [
                name for name, _, _ in shares if name.casefold() not in _DEFAULT_SHARES
            ]
            findings.append(
                _finding(
                    host=target,
                    title=f"SMB Shares Enumerated ({len(shares)})",
                    severity=Severity.LOW,
                    technique_id="T1135",
                    technique_name="Network Share Discovery",
                    tactic="Discovery",
                    evidence=_share_table_evidence(shares),
                    next_steps=(
                        [
                            "Review non-default shares for sensitive data: "
                            + ", ".join(non_default)
                            + "."
                        ]
                        if non_default
                        else ["Only default administrative shares were exposed."]
                    ),
                )
            )

        if files:
            label = share or "share"
            findings.append(
                _finding(
                    host=target,
                    title=f"SMB Share Contents Enumerated: {label} ({len(files)} file(s))",
                    severity=Severity.MEDIUM,
                    technique_id="T1039",
                    technique_name="Data from Network Shared Drive",
                    tactic="Collection",
                    evidence=_file_table_evidence(files),
                    next_steps=[
                        f"Download and review the {len(files)} file(s) from "
                        f"//{target or 'host'}/{label}.",
                    ],
                )
            )

        return ParsedResult(
            tool=self.tool_name,
            partial=False,
            hosts=hosts,
            credentials=[],
            findings=findings,
            domain_objects=domain_objects,
            raw_text=content,
        )


def _clean(content: str) -> str:
    text = _OSC_RE.sub("", content)
    text = _ANSI_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _target_and_share(content: str) -> tuple[str, str]:
    match = _TARGET_RE.search(content)
    if match:
        return match.group("target"), match.group("share")
    connect = re.search(
        r"do_connect:\s*Connection to\s+([A-Za-z0-9._-]+)", content, re.IGNORECASE
    )
    if connect:
        return connect.group(1), ""
    ipv4 = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
    return (ipv4.group(0) if ipv4 else ""), ""


def _parse_shares(content: str) -> list[tuple[str, str, str]]:
    if not _SHARE_HEADER_RE.search(content):
        return []
    shares: list[tuple[str, str, str]] = []
    for line in content.splitlines():
        match = _SHARE_ROW_RE.match(line)
        if not match:
            continue
        name = match.group("name")
        if name.casefold() == "sharename":
            continue
        shares.append((name, match.group("type"), match.group("comment").strip()))
    return shares


def _parse_files(content: str) -> list[tuple[str, str, str]]:
    files: list[tuple[str, str, str]] = []
    for line in content.splitlines():
        match = _FILE_ROW_RE.match(line)
        if not match:
            continue
        name = match.group("name").strip()
        if name in {".", ".."}:
            continue
        files.append((name, match.group("size"), match.group("date")))
    return files


def _share_table_evidence(shares: list[tuple[str, str, str]]) -> str:
    return "\n".join(
        f"{name}\t{share_type}\t{comment}".rstrip()
        for name, share_type, comment in shares
    )


def _file_table_evidence(files: list[tuple[str, str, str]]) -> str:
    return "\n".join(f"{name} ({size} bytes, {date})" for name, size, date in files)


def _finding(
    *,
    host: str,
    title: str,
    severity: Severity,
    technique_id: str,
    technique_name: str,
    tactic: str,
    evidence: str,
    next_steps: list[str],
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[MitreMatch(technique_id, technique_name, tactic, 1.0, "rule")],
        affected_hosts=[host] if host else [],
        evidence=evidence,
        next_steps=next_steps,
        defenses=[],
        chain_member=None,
        hash=finding_hash("smbclient", host, title),
    )
