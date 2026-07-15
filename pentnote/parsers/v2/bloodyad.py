"""bloodyAD parser.

Focused on the ``add shadowCredentials`` flow, whose output previously fell
through to the universal fallback and was mis-handled: the 64-char "sha256 of
RSA key" was split into two bogus 32-char hashes, and the recovered NT hash was
labelled generic pass-the-hash material rather than a real credential.

This parser recovers the NT hash as a credential, captures the stored TGT
(ccache) for Pass-the-Ticket, and records the KeyCredential RSA fingerprint as
context — never as splittable hash material.
"""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Credential, Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

_COMMAND_RE = re.compile(r"(?im)^#\s*command:\s*(?P<cmd>bloodyad\b.*)$")
_NT_RE = re.compile(r"(?im)^\s*NT\s*:\s*(?P<nt>[0-9a-fA-F]{32})\b")
_RSA_SHA256_RE = re.compile(
    r"sha256 of RSA key:\s*(?P<sha>[0-9a-fA-F]{64})\b", re.IGNORECASE
)
_CCACHE_RE = re.compile(r"ccache file\s+(?P<ccache>\S+)", re.IGNORECASE)
_TARGET_RE = re.compile(
    r"shadowcredentials\s+['\"]?(?P<target>[^'\"\s]+)['\"]?", re.IGNORECASE
)
_HOST_RE = re.compile(r"-H\s+(?P<host>\S+)")
_DOMAIN_RE = re.compile(r"-d\s+(?P<domain>\S+)")


class BloodyADParser(AbstractParser):
    """Parse bloodyAD shadow-credentials output into credentials and findings."""

    tool_name = "bloodyad"
    aliases = ("bloody-ad",)
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is bloodyAD output."""

        clean = self.clean(content)
        lowered = clean.casefold()
        if _COMMAND_RE.search(clean):
            return 0.97
        signals = 0
        if "bloodyad" in lowered:
            signals += 1
        if "keycredential generated" in lowered or "shadowcredentials" in lowered:
            signals += 1
        if "sha256 of rsa key" in lowered:
            signals += 1
        if "tgt stored in ccache" in lowered:
            signals += 1
        if signals >= 2:
            return 0.9
        if signals == 1:
            return 0.4
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        """Parse bloodyAD output into credentials and findings."""

        clean = self.clean(content)
        command = _match(_COMMAND_RE, clean, "cmd")
        host = _match(_HOST_RE, command, "host")
        domain = _match(_DOMAIN_RE, command, "domain")
        target = _match(_TARGET_RE, command, "target")
        nt_hash = _match(_NT_RE, clean, "nt")
        rsa_sha = _match(_RSA_SHA256_RE, clean, "sha")
        ccache = _match(_CCACHE_RE, clean, "ccache")

        credentials: list[Credential] = []
        findings: list[Finding] = []

        if nt_hash:
            account = target or "recovered account"
            source_host = host or domain or "unknown"
            credentials.append(
                Credential(
                    username=account,
                    secret=nt_hash,
                    secret_type="ntlm",
                    source_host=source_host,
                    domain=domain or None,
                )
            )
            findings.append(
                _shadow_credentials_finding(
                    account=account,
                    source_host=source_host,
                    nt_hash=nt_hash,
                    rsa_sha=rsa_sha,
                    ccache=ccache,
                )
            )

        return ParsedResult(
            tool=self.tool_name,
            partial=False,
            hosts=[],
            credentials=credentials,
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )


def _shadow_credentials_finding(
    *,
    account: str,
    source_host: str,
    nt_hash: str,
    rsa_sha: str,
    ccache: str,
) -> Finding:
    evidence_lines = [f"NT hash recovered for {account}: {nt_hash}"]
    if rsa_sha:
        evidence_lines.append(f"KeyCredential RSA key sha256: {rsa_sha}")
    if ccache:
        evidence_lines.append(f"TGT stored in ccache: {ccache}")

    next_steps = [
        f"Pass-the-hash or crack the recovered NT hash for {account} offline.",
    ]
    if ccache:
        next_steps.append(
            f"Use the stored TGT for Pass-the-Ticket: export KRB5CCNAME={ccache}."
        )
    next_steps.append(
        "Remove the injected KeyCredential from the target's "
        "msDS-KeyCredentialLink after testing."
    )

    severity = Severity.CRITICAL if "admin" in account.casefold() else Severity.HIGH
    return Finding(
        title=f"Shadow Credentials Abuse: NT hash recovered for {account}",
        severity=severity,
        mitre_matches=[
            MitreMatch(
                "T1556",
                "Modify Authentication Process",
                "Credential Access",
                0.9,
                "rule",
            ),
            MitreMatch(
                "T1550.003",
                "Use Alternate Authentication Material: Pass the Ticket",
                "Lateral Movement",
                0.9,
                "rule",
            ),
        ],
        affected_hosts=[source_host] if source_host != "unknown" else [],
        evidence="\n".join(evidence_lines),
        next_steps=next_steps,
        defenses=[],
        chain_member=None,
        hash=finding_hash("bloodyad", account, "shadow-credentials"),
    )


def _match(pattern: re.Pattern[str], text: str, group: str) -> str:
    if not text:
        return ""
    match = pattern.search(text)
    return match.group(group) if match else ""
