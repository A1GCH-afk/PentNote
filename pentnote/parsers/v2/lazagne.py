"""LaZagne credential dump parser."""

from __future__ import annotations

import re

from pentnote.core.deduplicator import finding_hash
from pentnote.models import Credential, Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser

STRONG_SIGNALS = (
    "LaZagne",
    "########## User",
    "---------------",
    "Password found",
    "[+] 1 passwords have been found",
    "lazagne.exe",
)

BROWSER_APPS = {"firefox", "chrome", "ie", "edge", "opera"}


class LaZagneParser(AbstractParser):
    """Parse LaZagne password recovery output."""

    tool_name = "lazagne"
    aliases = ("lazagne-exe",)
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        clean = self.clean(content)
        hits = sum(
            1 for signal in STRONG_SIGNALS if signal.casefold() in clean.casefold()
        )
        if "lazagne" in clean.casefold() and hits >= 1:
            return 0.95
        if hits >= 2:
            return 0.9
        return 0.0

    def parse(self, content: str) -> ParsedResult:
        clean = self.clean(content)
        creds = _credentials(clean)
        findings = _findings_for_credentials(creds)
        apps = sorted({cred["application"] for cred in creds})
        if len(apps) > 3:
            findings.append(_summary_finding(apps))
        credentials = [
            Credential(
                username=cred["username"],
                secret=cred["password"],
                secret_type=cred["secret_type"],
                source_host=cred["application"],
                domain=cred.get("url") or None,
            )
            for cred in creds
        ]
        return ParsedResult(
            self.tool_name,
            partial=False,
            hosts=[],
            credentials=credentials,
            findings=_dedupe(findings),
            domain_objects=[],
            raw_text=clean,
        )


def _credentials(content: str) -> list[dict[str, str]]:
    creds: list[dict[str, str]] = []
    current_user = ""
    current_app = ""
    block: dict[str, str] = {}
    for line in content.splitlines():
        user_match = re.search(r"#+\s*User:\s*(.+?)\s*#+", line, flags=re.I)
        if user_match:
            current_user = user_match.group(1).strip()
        app_match = re.search(r"-{3,}\s*(.+?)\s*-{3,}", line)
        if app_match:
            _append_cred(creds, block, current_app, current_user)
            block = {}
            current_app = app_match.group(1).strip()
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().casefold()
        value = value.strip()
        if key in {"url", "login", "username", "password", "hash"}:
            block[key] = value
        if key in {"password", "hash"}:
            _append_cred(creds, block, current_app, current_user)
            block = {}
    _append_cred(creds, block, current_app, current_user)
    return _dedupe_creds(creds)


def _append_cred(
    creds: list[dict[str, str]],
    block: dict[str, str],
    application: str,
    current_user: str,
) -> None:
    password = block.get("password") or block.get("hash")
    username = block.get("login") or block.get("username") or current_user
    if not password or not username:
        return
    app = application or "Windows Secrets"
    secret_type = "ntlm" if re.fullmatch(r"[0-9a-fA-F]{32}", password) else "plaintext"
    creds.append(
        {
            "application": app,
            "username": username,
            "password": password,
            "secret_type": secret_type,
            "url": block.get("url", ""),
        }
    )


def _findings_for_credentials(creds: list[dict[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    apps = sorted({cred["application"] for cred in creds})
    for app in apps:
        app_creds = [cred for cred in creds if cred["application"] == app]
        evidence = "\n".join(
            f"{cred['application']}: {cred['username']} / {cred['secret_type']}"
            for cred in app_creds
        )
        tags = _browser_tags(app)
        next_steps = ["Spray recovered credentials across in-scope services."]
        if tags:
            next_steps.append(f"Credential tags: {', '.join(tags)}")
        findings.append(
            Finding(
                title=f"Credentials Dumped: {app}",
                severity=Severity.CRITICAL,
                mitre_matches=[
                    MitreMatch(
                        "T1555",
                        "Credentials from Password Stores",
                        "Credential Access",
                        0.95,
                        "lazagne",
                    )
                ],
                affected_hosts=[app],
                evidence=evidence,
                next_steps=next_steps,
                defenses=[],
                chain_member=None,
                hash=finding_hash("lazagne", app, f"Credentials Dumped: {app}"),
            )
        )
    return findings


def _summary_finding(apps: list[str]) -> Finding:
    title = f"Multiple Credential Stores Compromised ({len(apps)})"
    return Finding(
        title=title,
        severity=Severity.CRITICAL,
        mitre_matches=[
            MitreMatch(
                "T1555",
                "Credentials from Password Stores",
                "Credential Access",
                0.95,
                "lazagne",
            ),
            MitreMatch(
                "T1003", "OS Credential Dumping", "Credential Access", 0.85, "lazagne"
            ),
        ],
        affected_hosts=apps,
        evidence=", ".join(apps),
        next_steps=["Prioritize credential validation and rotation."],
        defenses=[],
        chain_member=None,
        hash=finding_hash("lazagne", ",".join(apps), title),
    )


def _browser_tags(application: str) -> list[str]:
    app = application.casefold()
    for browser in BROWSER_APPS:
        if browser in app:
            return ["browser-cred", browser]
    return []


def _dedupe_creds(creds: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str, str]] = set()
    result: list[dict[str, str]] = []
    for cred in creds:
        key = (
            cred["application"].casefold(),
            cred["username"].casefold(),
            cred["password"],
            cred.get("url", "").casefold(),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(cred)
    return result


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result: list[Finding] = []
    for finding in findings:
        if finding.hash in seen:
            continue
        seen.add(finding.hash)
        result.append(finding)
    return result
