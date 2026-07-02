"""Kerbrute parser."""

from __future__ import annotations

from pyparsing import CaselessLiteral, ParseException, Suppress, Word, printables

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Credential, Finding, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

_USERNAME = (
    CaselessLiteral("VALID").suppress()
    + CaselessLiteral("USERNAME").suppress()
    + Suppress(":")
    + Word(printables)("principal")
)
_LOGIN = (
    CaselessLiteral("VALID").suppress()
    + CaselessLiteral("LOGIN").suppress()
    + Suppress(":")
    + Word(printables)("credential")
)


class KerbruteParser(AbstractParser):
    """Parse Kerbrute username and login output."""

    tool_name = "kerbrute"
    aliases = ()
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Score whether content is Kerbrute output."""

        lowered = content.casefold()
        score = 0.0
        if "kerbrute" in lowered:
            score += 0.4
        if "valid username" in lowered or "valid login" in lowered:
            score += 0.6
        return min(score, 1.0)

    def parse(self, content: str) -> ParsedResult:
        """Parse Kerbrute output."""

        credentials: list[Credential] = []
        findings: list[Finding] = []
        partial = False

        for line in self.clean(content).splitlines():
            stripped = line.strip()
            if not stripped or "[+]" not in stripped:
                continue
            payload = stripped.split("[+]", 1)[1].strip()
            username = _parse_username(payload)
            login = _parse_login(payload)
            if username is None and login is None:
                partial = True
                continue
            if username is not None:
                principal, domain = _principal_parts(username)
                credentials.append(
                    Credential(principal, "", "kerberos", "kerbrute", domain)
                )
                title = f"Kerbrute valid username: {principal}"
                findings.append(_finding(self.tool_name, title, Severity.LOW, stripped))
            if login is not None:
                principal, secret = login
                username_value, domain = _principal_parts(principal)
                credentials.append(
                    Credential(
                        username_value,
                        secret,
                        "plaintext",
                        "kerbrute",
                        domain,
                    )
                )
                title = f"Kerbrute valid login: {username_value}"
                findings.append(
                    _finding(self.tool_name, title, Severity.HIGH, stripped)
                )

        return ParsedResult(
            tool=self.tool_name,
            partial=partial,
            hosts=[],
            credentials=credentials,
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )


def _parse_username(payload: str) -> str | None:
    try:
        return _USERNAME.parse_string(payload, parse_all=True)["principal"]
    except ParseException:
        return None


def _parse_login(payload: str) -> tuple[str, str] | None:
    try:
        credential = _LOGIN.parse_string(payload, parse_all=True)["credential"]
    except ParseException:
        return None
    if ":" not in credential:
        return None
    principal, secret = credential.split(":", 1)
    return principal, secret


def _principal_parts(principal: str) -> tuple[str, str | None]:
    if "@" in principal:
        username, domain = principal.split("@", 1)
        return username, domain
    if "\\" in principal:
        domain, username = principal.split("\\", 1)
        return username, domain
    return principal, None


def _finding(tool: str, title: str, severity: Severity, evidence: str) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[],
        affected_hosts=[],
        evidence=evidence,
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash=finding_hash(tool, "", title),
    )
