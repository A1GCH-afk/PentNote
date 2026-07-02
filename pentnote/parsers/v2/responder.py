"""Responder parser."""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Credential, Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

STRONG_SIGNALS = (
    "[+] Listening for events...",
    "NTLMv2-SSP Hash",
    "NTLMv1 Hash",
    "[SMB] NTLMv",
    "[HTTP] NTLMv",
    "[LDAP] NTLMv",
    "Responder",
)


class ResponderParser(AbstractParser):
    """Parse Responder logs for captured Net-NTLM hashes."""

    tool_name = "responder"
    aliases = ("responder-log",)
    supported_extensions = (".log", ".txt")

    def can_parse(self, content: str) -> float:
        """Score whether content appears to be Responder output."""

        clean = self.clean(content)
        if any(signal in clean for signal in STRONG_SIGNALS):
            return 0.9
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        """Parse captured Net-NTLM credentials and findings."""

        clean = self.clean(content)
        captures = _parse_captures(clean)
        credentials: list[Credential] = []
        findings: list[Finding] = []
        seen_secrets: set[str] = set()

        for capture in captures:
            secret = capture["secret"]
            if secret in seen_secrets:
                continue
            seen_secrets.add(secret)
            username = capture["username"]
            domain = capture["domain"]
            source_host = capture["source_host"]
            secret_type = capture["secret_type"]
            credentials.append(
                Credential(
                    username=username,
                    secret=secret,
                    secret_type=secret_type,
                    source_host=source_host,
                    domain=domain,
                )
            )
            findings.append(
                _hash_finding(
                    tool=self.tool_name,
                    username=username,
                    domain=domain,
                    source_host=source_host,
                    secret_type=secret_type,
                    evidence=capture["evidence"],
                )
            )

        if len(captures) > 3:
            findings.append(_summary_finding(self.tool_name, captures))

        return ParsedResult(
            self.tool_name,
            partial=False,
            hosts=[],
            credentials=credentials,
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )


def _parse_captures(content: str) -> list[dict[str, str]]:
    captures: list[dict[str, str]] = []
    last_client = "unknown"
    last_identity: tuple[str, str] | None = None
    for line in content.splitlines():
        client = re.search(r"(?i)NTLMv[12]-SSP Client\s*:\s*(.+)$", line)
        if client:
            last_client = client.group(1).strip() or "unknown"
            continue
        username = re.search(r"(?i)NTLMv[12]-SSP Username\s*:\s*(.+)$", line)
        if username:
            last_identity = _parse_identity(username.group(1).strip())
            continue
        hash_match = re.search(
            r"(?i)NTLMv(?P<version>[12])(?:-SSP)? Hash\s*:\s*(.+)$", line
        )
        if not hash_match:
            continue
        secret = hash_match.group(2).strip()
        if not secret:
            continue
        domain, username_value, source_host = _identity_from_hash(secret)
        if last_identity and username_value == "unknown":
            domain, username_value = last_identity
        captures.append(
            {
                "username": username_value,
                "domain": domain,
                "secret": secret,
                "secret_type": (
                    "net-ntlmv2" if hash_match.group("version") == "2" else "net-ntlmv1"
                ),
                "source_host": last_client if last_client != "unknown" else source_host,
                "evidence": line.strip(),
            }
        )
    return captures


def _parse_identity(identity: str) -> tuple[str, str]:
    if "\\" in identity:
        domain, username = identity.split("\\", 1)
        return domain.strip(), username.strip()
    return "", identity.strip()


def _identity_from_hash(secret: str) -> tuple[str, str, str]:
    head, _, rest = secret.partition("::")
    domain = ""
    username = "unknown"
    if "\\" in head:
        domain, username = head.split("\\", 1)
    elif head:
        username = head
    source_host = rest.split(":", 1)[0].strip() if rest else ""
    if (
        not domain
        and source_host
        and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", source_host)
    ):
        domain = source_host
    return domain.strip(), username.strip() or "unknown", source_host


def _hash_finding(
    *,
    tool: str,
    username: str,
    domain: str,
    source_host: str,
    secret_type: str,
    evidence: str,
) -> Finding:
    principal = f"{domain}\\{username}" if domain else username
    mode = 5600 if secret_type == "net-ntlmv2" else 5500
    title = f"NTLM Hash Captured: {principal}"
    return Finding(
        title=title,
        severity=Severity.HIGH,
        mitre_matches=[
            MitreMatch(
                "T1557.001",
                "LLMNR/NBT-NS Poisoning and SMB Relay",
                "Credential Access",
                1.0,
                "rule",
            ),
            MitreMatch(
                "T1040",
                "Network Sniffing",
                "Credential Access",
                0.9,
                "rule",
            ),
        ],
        affected_hosts=[source_host],
        evidence=evidence,
        next_steps=[
            f"hashcat -m {mode} hash.txt rockyou.txt",
            "Attempt NTLM relay if signing disabled",
        ],
        defenses=[],
        chain_member=None,
        hash=finding_hash(tool, source_host, title),
    )


def _summary_finding(tool: str, captures: list[dict[str, str]]) -> Finding:
    evidence = "\n".join(capture["evidence"] for capture in captures)
    hosts = sorted({capture["source_host"] for capture in captures})
    title = f"Multiple NTLM Hashes Captured ({len(captures)})"
    return Finding(
        title=title,
        severity=Severity.CRITICAL,
        mitre_matches=[
            MitreMatch(
                "T1557.001",
                "LLMNR/NBT-NS Poisoning and SMB Relay",
                "Credential Access",
                1.0,
                "rule",
            ),
            MitreMatch("T1040", "Network Sniffing", "Credential Access", 0.9, "rule"),
            MitreMatch("T1078", "Valid Accounts", "Defense Evasion", 0.8, "rule"),
        ],
        affected_hosts=hosts,
        evidence=evidence,
        next_steps=[
            "Prioritize cracking captured hashes.",
            "Attempt NTLM relay where SMB signing is disabled.",
        ],
        defenses=[],
        chain_member=None,
        hash=finding_hash(tool, ",".join(hosts), title),
    )
