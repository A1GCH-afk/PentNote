"""Generic C2 console log parser scaffold."""

from __future__ import annotations

import hashlib
import re

from pentnote.models import Credential, Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser
from pentnote.parsers.c2.base import (
    C2Credential,
    C2Download,
    C2Parser,
    C2ParseResult,
    C2Session,
)

SESSION_RE = re.compile(
    r"(?i)\b(?:session|beacon|demon(?:\s+id)?)\s+(?P<id>[a-z0-9._:-]+)"
    r".*?(?:from|on)\s+(?P<host>[a-z0-9_.-]+|\d{1,3}(?:\.\d{1,3}){3})"
)
DOWNLOAD_RE = re.compile(
    r"(?i)\b(?:download(?:ed)?|loot(?:ed)?)\b.*?"
    r"(?P<path>(?:[a-z]:\\|/)[^\s'\"`]+)"
    r"(?:.*?\b(?:from|on)\s+(?P<host>[a-z0-9_.-]+|\d{1,3}(?:\.\d{1,3}){3}))?"
)
CREDENTIAL_RE = re.compile(
    r"(?i)\b(?P<user>[a-z0-9_.-]+(?:\\[a-z0-9_.-]+|@[a-z0-9_.-]+)?)"
    r"\s*[:=]\s*(?P<secret>[^\s'\"`]{4,})"
)
NTLM_RE = re.compile(r"(?i)\b[a-f0-9]{32}\b")

SLIVER_SIGNALS = {
    "strong": (
        "[*] Session",
        "sliver >",
        "[server]",
        "Listening on",
    ),
    "weak": (
        "implant",
        "beacon",
        "mtls://",
        "wg://",
    ),
}
HAVOC_SIGNALS = {
    "strong": (
        "Demon",
        "havoc >",
        "[+] New agent",
        "TeamServer",
    ),
    "weak": (
        "beacon",
        "checkin",
        "pivot",
    ),
}


class GenericC2LogParser(AbstractParser, C2Parser):
    """Extract common C2 events from Sliver/Havoc-style console logs."""

    tool_name = "generic-c2"
    aliases = ("c2-generic",)
    supported_extensions = (".log", ".txt")
    framework = "generic-c2"

    def fingerprint(self, content: str) -> float:
        """Return low generic confidence for internal/dev use only."""

        return self.can_parse(content)

    def can_parse(self, content: str) -> float:
        return max(
            framework_signal_confidence(content, SLIVER_SIGNALS),
            framework_signal_confidence(content, HAVOC_SIGNALS),
        )

    def parse_c2(self, content: str) -> C2ParseResult:
        clean = self.clean(content)
        sessions = [
            C2Session(session_id=match.group("id"), hostname=match.group("host"))
            for match in SESSION_RE.finditer(clean)
        ]
        downloads = [
            C2Download(path=match.group("path"), host=match.group("host"))
            for match in DOWNLOAD_RE.finditer(clean)
        ]
        credentials = [
            _credential_from_match(match)
            for match in CREDENTIAL_RE.finditer(clean)
            if _looks_like_credential(match.group("secret"))
        ]
        notes: list[str] = []
        notes.extend(
            f"C2 session {item.session_id} observed on {item.hostname}"
            for item in sessions
        )
        notes.extend(f"C2 download observed: {item.path}" for item in downloads)
        return C2ParseResult(
            framework=self.framework,
            sessions=sessions,
            downloads=downloads,
            credentials=credentials,
            notes=notes,
        )

    def parse(self, content: str) -> ParsedResult:
        result = self.parse_c2(content)
        credentials = [
            Credential(
                username=item.username,
                secret=item.secret,
                secret_type=item.secret_type,
                source_host=item.host or "unknown",
                domain=item.domain,
            )
            for item in result.credentials
        ]
        findings = _findings_from_c2(result)
        return ParsedResult(
            tool=self.tool_name,
            partial=False,
            hosts=[],
            credentials=credentials,
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )


def _credential_from_match(match: re.Match[str]) -> C2Credential:
    raw_user = match.group("user")
    domain: str | None = None
    username = raw_user
    if "\\" in raw_user:
        domain, username = raw_user.split("\\", 1)
    elif "@" in raw_user:
        username, domain = raw_user.split("@", 1)
    secret = match.group("secret")
    return C2Credential(
        username=username,
        domain=domain,
        secret=secret,
        secret_type="ntlm" if NTLM_RE.fullmatch(secret) else "plaintext",
    )


def _looks_like_credential(secret: str) -> bool:
    lowered = secret.casefold()
    if lowered in {"true", "false", "null", "none", "session", "download"}:
        return False
    if secret.startswith("//"):
        return False
    return len(secret) >= 4


def framework_signal_confidence(
    content: str,
    signals: dict[str, tuple[str, ...]],
) -> float:
    """Score C2 framework confidence from strict signal sets."""

    strong_hits = _signal_hits(content, signals["strong"])
    if strong_hits == 0:
        return 0.0
    weak_hits = _signal_hits(content, signals["weak"])
    return min(1.0, (strong_hits * 0.4) + (weak_hits * 0.1))


def _signal_hits(content: str, signals: tuple[str, ...]) -> int:
    lowered = content.casefold()
    return sum(1 for signal in signals if signal.casefold() in lowered)


def _findings_from_c2(result: C2ParseResult) -> list[Finding]:
    findings: list[Finding] = []
    for session in result.sessions:
        findings.append(_session_finding(result.framework, session))
    for download in result.downloads:
        findings.append(
            Finding(
                title=f"C2 download observed: {download.path}",
                severity=Severity.HIGH,
                mitre_matches=[
                    MitreMatch(
                        "T1048",
                        "Exfiltration Over Alternative Protocol",
                        "Exfiltration",
                        0.75,
                        "rule",
                    ),
                    MitreMatch(
                        "T1105",
                        "Ingress Tool Transfer",
                        "Command and Control",
                        0.6,
                        "rule",
                    ),
                ],
                affected_hosts=[download.host] if download.host else [],
                evidence=download.model_dump_json(),
                next_steps=[
                    f"Review transferred file path: {download.path}",
                    "Correlate C2 file transfer with host telemetry.",
                ],
                defenses=[],
                chain_member="c2-download",
                hash=_hash("download", download.path, download.host or ""),
            )
        )
    return findings


def _session_finding(framework: str, session: C2Session) -> Finding:
    host = session.hostname or session.address or "unknown"
    return Finding(
        title=f"C2 session observed: {session.session_id} on {host}",
        severity=Severity.CRITICAL,
        mitre_matches=_session_mitre_matches(framework),
        affected_hosts=[host] if host != "unknown" else [],
        evidence=session.model_dump_json(),
        next_steps=[
            f"Enumerate host: cme smb {host} --shares",
            "Check for persistence: reg query "
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            "Check running processes: tasklist /v",
        ],
        defenses=[],
        chain_member="c2-session",
        hash=_hash(framework, "session", session.session_id, host),
    )


def _session_mitre_matches(framework: str) -> list[MitreMatch]:
    base = [
        MitreMatch(
            "T1071.001",
            "Web Protocols",
            "Command and Control",
            0.85,
            "rule",
        ),
        MitreMatch(
            "T1055",
            "Process Injection",
            "Defense Evasion",
            0.6,
            "rule",
        ),
    ]
    if framework == "sliver":
        base.append(
            MitreMatch(
                "T1573.002",
                "Asymmetric Cryptography",
                "Command and Control",
                0.7,
                "rule",
            )
        )
        base.append(
            MitreMatch(
                "T1095",
                "Non-Application Layer Protocol",
                "Command and Control",
                0.7,
                "rule",
            )
        )
    elif framework == "havoc":
        base.append(
            MitreMatch(
                "T1095",
                "Non-Application Layer Protocol",
                "Command and Control",
                0.7,
                "rule",
            )
        )
    return base


def _hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]
