"""MITRE match scoring helpers."""

from __future__ import annotations

from pentnote.models import Finding, Host, MitreMatch, RiskScore, Severity

SEVERITY_SCORES = {
    Severity.CRITICAL: 4.0,
    Severity.HIGH: 3.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.1,
}

LATERAL_TTPS = {
    "T1021.001",
    "T1021.002",
    "T1021.004",
    "T1021.006",
    "T1550.002",
    "T1558.003",
}

CREDENTIAL_TTPS = {
    "T1003.001",
    "T1003.002",
    "T1003.006",
    "T1558.003",
    "T1558.004",
    "T1078",
    "T1110",
}

EASY_EXPLOIT_TTPS = {
    "T1557.001",
    "T1558.004",
    "T1190",
    "T1135",
}


def merge_matches(matches: list[MitreMatch]) -> list[MitreMatch]:
    """Deduplicate technique matches and keep the strongest confidence."""

    best_by_id: dict[str, MitreMatch] = {}
    for match in matches:
        current = best_by_id.get(match.technique_id)
        if current is None or _is_stronger(match, current):
            best_by_id[match.technique_id] = match
    return rank_matches(list(best_by_id.values()))


def rank_matches(matches: list[MitreMatch]) -> list[MitreMatch]:
    """Sort matches by confidence and stable technique ID."""

    return sorted(
        matches,
        key=lambda item: (item.confidence, item.technique_id),
        reverse=True,
    )


def severity_for_host(host: Host) -> Severity:
    """Score host severity from observed open services."""

    open_ports = {port.number for port in host.ports if port.state == "open"}
    if not open_ports:
        return Severity.INFO
    if open_ports & {88, 389, 636, 3268}:
        return Severity.CRITICAL
    if open_ports & {3389, 445}:
        return Severity.HIGH
    if open_ports & {22, 80, 443}:
        return Severity.MEDIUM
    return Severity.LOW


def host_severity_reason(host: Host) -> str:
    """Return the human-readable reason for a host severity score."""

    open_ports = {port.number for port in host.ports if port.state == "open"}
    severity = severity_for_host(host)
    if severity == Severity.CRITICAL:
        return "Domain controller indicators detected"
    if severity == Severity.HIGH:
        if 3389 in open_ports:
            return "RDP open - remote desktop attack surface"
        return "SMB open and signing has not been checked yet"
    if severity == Severity.MEDIUM:
        services = []
        if 22 in open_ports:
            services.append("SSH")
        if 80 in open_ports:
            services.append("HTTP")
        if 443 in open_ports:
            services.append("HTTPS")
        return f"{' and '.join(services)} open — potential remote access and web attack surface"
    if severity == Severity.LOW:
        return "Only low-risk or info-only services detected"
    return "No open ports detected"


def score_finding(
    finding: Finding,
    in_chain: bool = False,
) -> RiskScore:
    """Return a weighted risk score for a finding."""

    severity_score = SEVERITY_SCORES.get(finding.severity, 1.0)
    ttps = {match.technique_id for match in finding.mitre_matches}
    exploitability = 0.8 if _has_ttp(ttps, EASY_EXPLOIT_TTPS) else 0.4
    lateral_potential = 0.9 if _has_ttp(ttps, LATERAL_TTPS) else 0.1
    credential_exposure = 0.9 if _has_ttp(ttps, CREDENTIAL_TTPS) else 0.1
    chain_bonus = 0.5 if in_chain else 0.0
    total = (
        (severity_score * 0.4)
        + (exploitability * 0.2)
        + (lateral_potential * 0.2)
        + (credential_exposure * 0.15)
        + chain_bonus
    )
    return RiskScore(
        severity_score=severity_score,
        exploitability=exploitability,
        lateral_potential=lateral_potential,
        credential_exposure=credential_exposure,
        chain_bonus=chain_bonus,
        total=min(5.0, round(total, 2)),
    )


def _is_stronger(candidate: MitreMatch, current: MitreMatch) -> bool:
    if candidate.confidence != current.confidence:
        return candidate.confidence > current.confidence
    return candidate.source == "rule" and current.source != "rule"


def _has_ttp(observed: set[str], wanted: set[str]) -> bool:
    return any(
        technique_id == candidate or technique_id.startswith(candidate + ".")
        for technique_id in observed
        for candidate in wanted
    )
