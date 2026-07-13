"""Final report generation."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from pathlib import Path

from pentnote.generators.markdown import _assign_target_group, template_env
from pentnote.mitre.chain_detector import DetectedChain, detect_chains
from pentnote.mitre.defends import defense_tuples_for_matches
from pentnote.mitre.scorer import score_finding
from pentnote.models import (
    DefenseRow,
    Engagement,
    EngagementType,
    Finding,
    Host,
    RemediationItem,
    Severity,
)


def write_report(
    findings: list[Finding],
    output_dir: Path,
    *,
    engagement_name: str,
    report_format: str = "markdown",
    with_defenses: bool = False,
    redact: bool = False,
    engagement: Engagement | None = None,
    hosts: list[Host] | None = None,
    previous_findings: list[Finding] | None = None,
) -> list[Path]:
    """Write Markdown and/or HTML reports."""

    output_dir.mkdir(parents=True, exist_ok=True)
    formats = ("markdown", "html") if report_format == "both" else (report_format,)
    paths: list[Path] = []
    chains = detect_chains(findings)
    sorted_findings = _score_and_sort_findings(findings, chains)
    report_engagement = engagement or Engagement(
        root=output_dir.parent,
        name=engagement_name,
        scope=[],
        created_at=_now_iso(),
    )
    report_hosts = hosts or _hosts_from_findings(findings)
    executive_summary = build_executive_summary(
        sorted_findings,
        chains,
        report_hosts,
        report_engagement,
    )
    summary = _legacy_summary(executive_summary)
    mitre_coverage = _mitre_coverage(sorted_findings)
    donut_chart = build_donut_chart_data(
        summary["critical"],
        summary["high"],
        summary["medium"],
        summary["low"],
        summary["info"],
    )
    top_risks = sorted(
        sorted_findings,
        key=lambda finding: finding.risk_score.total if finding.risk_score else 0.0,
        reverse=True,
    )[:5]
    tactic_bars = build_tactic_bars(sorted_findings)
    findings_by_tool = _group_by_tool(sorted_findings)
    remediation_items = build_remediation_list(sorted_findings, previous_findings)
    remediated_findings = (
        detect_remediated(sorted_findings, previous_findings)
        if previous_findings is not None
        else []
    )
    for item in formats:
        template_name = "report.md.j2" if item == "markdown" else "report.html.j2"
        suffix = "md" if item == "markdown" else "html"
        path = output_dir / f"pentnote-report.{suffix}"
        path.write_text(
            template_env()
            .get_template(template_name)
            .render(
                findings=sorted_findings,
                engagement_name=engagement_name,
                with_defenses=with_defenses,
                redact=redact,
                redacted=redacted,
                summary=summary,
                executive_summary=executive_summary,
                unique_hosts=executive_summary["affected_hosts"],
                affected_asset_rows=_affected_asset_rows(
                    executive_summary["affected_hosts"],
                    sorted_findings,
                ),
                top_risk_rows=_top_risk_rows(executive_summary["top_risks"]),
                donut_chart=donut_chart,
                top_risks=top_risks,
                tactic_bars=tactic_bars,
                findings_by_tool=findings_by_tool,
                remediation_items=remediation_items,
                remediated_findings=remediated_findings,
                remediated_count=len(remediated_findings),
                target_group_rows=_target_group_rows(
                    report_engagement,
                    sorted_findings,
                ),
                top_findings=executive_summary["top_risks"],
                chains=chains,
                mitre_coverage=mitre_coverage,
                defense_rows={
                    finding.hash: defense_tuples_for_matches(finding.mitre_matches)
                    for finding in sorted_findings
                },
                iso_timestamp=_now_iso(),
            ),
            encoding="utf-8",
        )
        paths.append(path)
    return paths


def build_executive_summary(
    findings: list[Finding],
    chains: list[DetectedChain],
    hosts: list[Host],
    engagement: Engagement,
) -> dict:
    """Build the executive-summary report context."""

    by_severity = {
        "critical": [f for f in findings if f.severity == Severity.CRITICAL],
        "high": [f for f in findings if f.severity == Severity.HIGH],
        "medium": [f for f in findings if f.severity == Severity.MEDIUM],
        "low": [f for f in findings if f.severity == Severity.LOW],
        "info": [f for f in findings if f.severity == Severity.INFO],
    }
    top_risks = sorted(
        findings,
        key=lambda finding: (
            -(finding.risk_score.total if finding.risk_score else 0.0),
            _severity_rank(finding),
            -len(finding.affected_hosts),
            finding.title.casefold(),
        ),
    )[:5]
    affected_hosts = sorted(
        {host for finding in findings for host in finding.affected_hosts}
    )
    if not affected_hosts:
        affected_hosts = sorted({host.ip for host in hosts})
    return {
        "engagement_name": engagement.name,
        "client_name": engagement.client_name,
        "engagement_type": engagement.engagement_type.value,
        "engagement_type_label": _engagement_type_report_label(
            engagement.engagement_type
        ),
        "scope": engagement.scope,
        "operator": engagement.operator,
        "start_date": engagement.start_date,
        "start_date_label": _format_date_label(engagement.start_date),
        "total_findings": len(findings),
        "by_severity": by_severity,
        "top_risks": top_risks,
        "affected_hosts": affected_hosts,
        "chains_detected": chains,
        "total_hosts": len(hosts) if hosts else len(affected_hosts),
        "critical_count": len(by_severity["critical"]),
        "high_count": len(by_severity["high"]),
        "medium_count": len(by_severity["medium"]),
        "low_count": len(by_severity["low"]),
        "info_count": len(by_severity["info"]),
    }


def build_remediation_list(
    findings: list[Finding],
    previous_findings: list[Finding] | None = None,
) -> list[RemediationItem]:
    """Build a priority-ordered remediation roadmap."""

    del previous_findings
    items: list[RemediationItem] = []
    ranked_findings = sorted(
        findings,
        key=lambda finding: (
            finding.risk_score.total if finding.risk_score else 0.0,
            -_severity_rank(finding),
            finding.title.casefold(),
        ),
        reverse=True,
    )
    for priority, finding in enumerate(ranked_findings, start=1):
        items.append(
            RemediationItem(
                finding_title=finding.title,
                severity=finding.severity,
                risk_score=finding.risk_score.total if finding.risk_score else 0.0,
                d3fend_ids=_d3fend_ids(finding),
                recommendation=_generate_recommendation(finding),
                effort=_estimate_effort(finding),
                priority=priority,
            )
        )
    return items


def build_donut_chart_data(
    critical: int,
    high: int,
    medium: int,
    low: int,
    info: int,
) -> dict:
    """Build pure-SVG donut chart segment data."""

    total = critical + high + medium + low + info
    colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#16a34a",
        "info": "#0284c7",
    }
    if total == 0:
        return {"segments": [], "total": 0, "empty_color": "#94a3b8"}
    counts = {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
    }
    segments = []
    start_angle = -90.0
    cx, cy, r_outer, r_inner = 100.0, 100.0, 80.0, 50.0
    for name, count in counts.items():
        if count == 0:
            continue
        sweep = (count / total) * 360.0
        end_angle = start_angle + sweep
        segments.append(
            {
                "name": name,
                "count": count,
                "color": colors[name],
                "path": _arc_path(cx, cy, r_outer, r_inner, start_angle, end_angle),
            }
        )
        start_angle = end_angle
    return {"segments": segments, "total": total}


def _arc_path(
    cx: float,
    cy: float,
    r_outer: float,
    r_inner: float,
    start_deg: float,
    end_deg: float,
) -> str:
    """Return an SVG path for a donut segment."""

    def pt(radius: float, degrees: float) -> tuple[float, float]:
        radians = math.radians(degrees)
        return cx + radius * math.cos(radians), cy + radius * math.sin(radians)

    if abs(end_deg - start_deg) >= 360:
        end_deg = start_deg + 359.99

    large = 1 if (end_deg - start_deg) > 180 else 0
    x1o, y1o = pt(r_outer, start_deg)
    x2o, y2o = pt(r_outer, end_deg)
    x1i, y1i = pt(r_inner, end_deg)
    x2i, y2i = pt(r_inner, start_deg)
    return (
        f"M {x1o:.2f} {y1o:.2f} "
        f"A {r_outer:.2f} {r_outer:.2f} 0 {large} 1 {x2o:.2f} {y2o:.2f} "
        f"L {x1i:.2f} {y1i:.2f} "
        f"A {r_inner:.2f} {r_inner:.2f} 0 {large} 0 {x2i:.2f} {y2i:.2f} Z"
    )


def build_tactic_bars(findings: list[Finding]) -> list[dict]:
    """Build tactic coverage bars for report."""

    tactic_ttps: dict[str, set[str]] = {}
    for finding in findings:
        for match in finding.mitre_matches:
            tactic_ttps.setdefault(match.tactic, set()).add(match.technique_id)
    max_count = max((len(ttps) for ttps in tactic_ttps.values()), default=0) or 1
    return [
        {
            "tactic": tactic,
            "count": len(ttps),
            "ttps": sorted(ttps),
            "percent": int((len(ttps) / max_count) * 100),
        }
        for tactic, ttps in sorted(tactic_ttps.items())
    ]


def detect_remediated(
    current_findings: list[Finding],
    previous_findings: list[Finding] | None,
) -> list[Finding]:
    """Return previous findings that no longer appear in current results."""

    if not previous_findings:
        return []
    current_hashes = {finding.hash for finding in current_findings}
    current_titles = {finding.title.casefold() for finding in current_findings}
    return [
        finding
        for finding in previous_findings
        if finding.hash not in current_hashes
        and finding.title.casefold() not in current_titles
    ]


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _engagement_type_report_label(engagement_type: EngagementType | str) -> str:
    labels = {
        EngagementType.INTERNAL_AD: "Internal Active Directory",
        EngagementType.EXTERNAL_WEB: "External Web",
        EngagementType.FULL_SCOPE: "Full Scope",
        EngagementType.RED_TEAM: "Red Team",
        EngagementType.ASSUMED_BREACH: "Assumed Breach",
    }
    return labels[EngagementType(engagement_type)]


def _format_date_label(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    return f"{parsed.strftime('%B')} {parsed.day}, {parsed.year}"


def _severity_rank(finding: Finding) -> int:
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return order.get(finding.severity, 99)


def _score_and_sort_findings(
    findings: list[Finding],
    chains: list[DetectedChain],
) -> list[Finding]:
    chain_ttps = {
        technique_id for chain in chains for technique_id in chain.matched_ttps
    }
    for finding in findings:
        finding_ttps = {match.technique_id for match in finding.mitre_matches}
        in_chain = bool(finding.chain_member) or bool(finding_ttps & chain_ttps)
        finding.risk_score = score_finding(finding, in_chain=in_chain)
    return sorted(
        findings,
        key=lambda finding: (
            finding.risk_score.total if finding.risk_score else 0.0,
            -_severity_rank(finding),
            len(finding.affected_hosts),
            finding.title.casefold(),
        ),
        reverse=True,
    )


def _legacy_summary(executive_summary: dict) -> dict[str, int]:
    return {
        "critical": executive_summary["critical_count"],
        "high": executive_summary["high_count"],
        "medium": executive_summary["medium_count"],
        "low": executive_summary["low_count"],
        "info": executive_summary["info_count"],
        "hosts": len(executive_summary["affected_hosts"]),
        "chains": len(executive_summary["chains_detected"]),
    }


def _hosts_from_findings(findings: list[Finding]) -> list[Host]:
    return [
        Host(ip=host)
        for host in sorted(
            {host for finding in findings for host in finding.affected_hosts}
        )
    ]


def _affected_asset_rows(
    affected_hosts: list[str],
    findings: list[Finding],
) -> list[tuple[str, int]]:
    return [
        (
            host,
            sum(1 for finding in findings if host in finding.affected_hosts),
        )
        for host in affected_hosts
    ]


def _target_group_rows(
    engagement: Engagement,
    findings: list[Finding],
) -> list[dict[str, object]]:
    if not engagement.target_groups:
        return []
    rows = []
    for group in engagement.target_groups:
        group_findings = [
            finding
            for finding in findings
            if finding.target_group == group.name
            or any(
                _assign_target_group(host, [group]) == group.name
                for host in finding.affected_hosts
            )
        ]
        rows.append(
            {
                "name": group.name,
                "scope": group.scope,
                "findings": group_findings,
            }
        )
    return rows


def _top_risk_rows(findings: list[Finding]) -> list[dict[str, object]]:
    return [
        {
            "rank": index,
            "finding": finding,
            "risk_score": finding.risk_score.total if finding.risk_score else 0.0,
            "exploitability": _exploitability_label(finding),
        }
        for index, finding in enumerate(findings, start=1)
    ]


def _exploitability_label(finding: Finding) -> str:
    if finding.risk_score is None:
        return "Unknown"
    if finding.risk_score.exploitability >= 0.8:
        return "Easy"
    if finding.risk_score.exploitability >= 0.4:
        return "Medium"
    return "Low"


def _d3fend_ids(finding: Finding) -> list[str]:
    ids: list[str] = []
    for defense in finding.defenses:
        if isinstance(defense, DefenseRow):
            ids.append(defense.defend_id)
        elif isinstance(defense, str):
            ids.append(defense)
    if not ids:
        ids.extend(
            row.defend_id for row in defense_tuples_for_matches(finding.mitre_matches)
        )
    return list(dict.fromkeys(ids))


def _generate_recommendation(finding: Finding) -> str:
    recommendations = {
        "smb signing disabled": (
            "Enable SMB signing via Group Policy: "
            "Network security: Digitally sign communications."
        ),
        "kerberoastable": (
            "Use strong passwords (25+ chars) for service accounts. "
            "Consider Group Managed Service Accounts (gMSA)."
        ),
        "ntlm hash": (
            "Enforce password rotation. " "Enable Protected Users security group."
        ),
        "adcs esc": ("Review AD CS template permissions. Restrict enrollment rights."),
        "smb relay": ("Enable SMB signing and LDAP signing. Disable LLMNR and NBT-NS."),
    }
    title_lower = finding.title.casefold()
    for key, recommendation in recommendations.items():
        if key in title_lower:
            return recommendation
    d3fend_ids = _d3fend_ids(finding)
    if d3fend_ids:
        return "Review and remediate based on D3FEND guidance: " + ", ".join(
            d3fend_ids[:3]
        )
    return "Validate remediation with the asset owner."


def _estimate_effort(finding: Finding) -> str:
    title_lower = finding.title.casefold()
    ttps = {match.technique_id for match in finding.mitre_matches}
    if "smb signing" in title_lower or "smb relay" in title_lower:
        return "Low"
    if "ntlm hash" in title_lower or ttps & {"T1003.001", "T1003.002", "T1003.006"}:
        return "Low"
    if "kerberoastable" in title_lower or ttps & {"T1558.003", "T1558.004"}:
        return "Medium"
    if "adcs esc" in title_lower or "certipy" in title_lower or "T1649" in ttps:
        return "High"
    if "web" in title_lower or "http" in title_lower or "T1190" in ttps:
        return "Medium"
    return "Medium"


def _mitre_coverage(findings: list[Finding]) -> list[str]:
    return sorted(
        {match.technique_id for finding in findings for match in finding.mitre_matches}
    )


def _group_by_tool(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        source = "unknown"
        if finding.source_command:
            source = finding.source_command.split(maxsplit=1)[0]
        grouped.setdefault(source, []).append(finding)
    return grouped


def redacted(value: object) -> str:
    """Render a non-empty template value as the literal ``[REDACTED]`` marker."""
    text = str(value if value is not None else "")
    return "[REDACTED]" if text else text
