"""MITRE tactic coverage reporting."""

from __future__ import annotations

import json
from importlib import resources

from pentnote.mitre.classifier import ALWAYS_ADD, PORT_MITRE_RULES, _load_attack_db
from pentnote.models import Finding

ATTACK_ENTERPRISE_TOTAL = 196
ALL_HIGH_VALUE = {
    "T1059.001",
    "T1059.003",
    "T1047",
    "T1053.005",
    "T1543.003",
    "T1547.001",
    "T1562.001",
    "T1070.001",
    "T1027",
    "T1071.001",
    "T1090",
    "T1572",
    "T1048",
    "T1567",
}
TECHNIQUE_NAME_FALLBACKS = {
    "T1027": "Obfuscated Files or Information",
    "T1047": "Windows Management Instrumentation",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1053.005": "Scheduled Task",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1070.001": "Clear Windows Event Logs",
    "T1071.001": "Web Protocols",
    "T1090": "Proxy",
    "T1543.003": "Windows Service",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1562.001": "Disable or Modify Tools",
    "T1567": "Exfiltration Over Web Service",
    "T1572": "Protocol Tunneling",
}

PARSER_TTP_COVERAGE = {
    "nmap": [
        "T1046",
        "T1021.001",
        "T1021.002",
        "T1021.003",
        "T1021.004",
        "T1021.006",
        "T1069.002",
        "T1083",
        "T1190",
        "T1210",
        "T1557.001",
    ],
    "crackmapexec": ["T1021.002", "T1078", "T1550.002", "T1557.001"],
    "impacket": ["T1003.001", "T1003.002", "T1003.006", "T1550.002"],
    "impacket-secretsdump": ["T1003.002", "T1003.006", "T1550.002"],
    "rubeus": ["T1550.003", "T1558.003", "T1558.004"],
    "certipy": ["T1557.001", "T1649"],
    "mimikatz": ["T1003.001"],
    "enum4linux": ["T1069.002", "T1110.001", "T1135"],
    "sqlmap": ["T1190"],
    "nikto": ["T1190"],
    "nuclei": ["T1190"],
    "gobuster": ["T1083"],
    "feroxbuster": ["T1083"],
    "kerbrute": ["T1110.003"],
    "bloodhound": ["T1069.002", "T1482"],
    "responder": ["T1040", "T1557.001"],
    "winpeas": ["T1003.002", "T1543.003", "T1548.002", "T1552.001", "T1574.009"],
    "linpeas": ["T1003.008", "T1053.003", "T1068", "T1548.001", "T1548.003"],
    "c2": [
        "T1008",
        "T1055",
        "T1055.012",
        "T1070.004",
        "T1071.001",
        "T1071.002",
        "T1071.004",
        "T1090",
        "T1090.001",
        "T1090.003",
        "T1095",
        "T1102",
        "T1105",
        "T1132.001",
        "T1497.003",
        "T1571",
        "T1572",
        "T1573.002",
    ],
}


def tactic_coverage(findings: list[Finding]) -> dict[str, float]:
    """Return tactic coverage percentages across ATT&CK tactic totals."""

    discovered = _discovered_ttps(findings)
    if not discovered:
        return {}
    return {
        tactic: round(_tactic_coverage(techniques, discovered) * 100, 2)
        for tactic, techniques in _tactic_techniques().items()
    }


def discovered_ttps_by_tactic(findings: list[Finding]) -> dict[str, list[str]]:
    """Return discovered TTPs grouped by ATT&CK tactic."""

    technique_tactics = _technique_tactics()
    grouped: dict[str, set[str]] = {tactic: set() for tactic in _tactic_techniques()}
    for finding in findings:
        for match in finding.mitre_matches:
            technique_id = match.technique_id
            tactics = set(technique_tactics.get(technique_id, []))
            if match.tactic != "Unknown":
                tactics.add(match.tactic)
            for tactic in tactics:
                grouped.setdefault(tactic, set()).add(technique_id)
    return {tactic: sorted(ttps) for tactic, ttps in grouped.items()}


def total_techniques_by_tactic() -> dict[str, int]:
    """Return ATT&CK technique totals by tactic."""

    return {
        tactic: len(techniques) for tactic, techniques in _tactic_techniques().items()
    }


def format_coverage_output(
    tactic_coverage: dict[str, float],
    discovered_by_tactic: dict[str, list[str]],
    total_by_tactic: dict[str, int],
) -> list[str]:
    """Format tactic coverage with counts and a compact progress bar."""

    lines: list[str] = []
    for tactic, pct in sorted(tactic_coverage.items(), key=lambda item: -item[1]):
        discovered_count = len(discovered_by_tactic.get(tactic, []))
        total = total_by_tactic.get(tactic, 0)
        ratio = pct / 100 if pct > 1 else pct
        bar_len = min(10, max(0, int(ratio * 10)))
        bar = "█" * bar_len + "░" * (10 - bar_len)
        star = " ✓" if discovered_count > 0 else ""
        lines.append(
            f"{tactic:<25} {bar}  "
            f"{discovered_count}/{total}  "
            f"({discovered_count} found){star}"
        )
    return lines


def _is_covered(technique_id: str, discovered: set[str]) -> bool:
    """
    Return True when a technique or one of its sub-techniques is discovered.

    T1021 is covered by T1021.002, and T1021.002 is covered directly by
    T1021.002. If both parent and child exist in a tactic list, each list item
    is evaluated independently.
    """

    if technique_id in discovered:
        return True
    prefix = technique_id + "."
    return any(candidate.startswith(prefix) for candidate in discovered)


def _tactic_coverage(
    tactic_techniques: list[str],
    discovered_ttps: set[str],
) -> float:
    """Return tactic coverage as a 0.0-1.0 fraction."""

    if not tactic_techniques:
        return 0.0
    covered = sum(
        1
        for technique_id in tactic_techniques
        if _is_covered(technique_id, discovered_ttps)
    )
    return covered / len(tactic_techniques)


def _builtin_ttp_coverage() -> dict[str, list[str]]:
    """Return all TTPs PentNote knows about, grouped by source."""

    port_ttps = {
        technique_id
        for rules in [ALWAYS_ADD, *PORT_MITRE_RULES.values()]
        for technique_id, _name, _tactic, _confidence in rules
    }
    finding_rules = {
        technique_id
        for values in _load_rules_json().values()
        for technique_id in values
    }
    chain_ttps = {
        technique_id
        for definition in _load_chain_json().values()
        for technique_id in [
            *definition.get("required_ttps", []),
            *definition.get("optional_ttps", []),
        ]
    }
    return {
        "port_rules": sorted(port_ttps),
        "finding_rules": sorted(finding_rules),
        "chains": sorted(chain_ttps),
    }


def tool_ttp_coverage() -> dict[str, list[str]]:
    """Return TTP coverage grouped by parser and built-in rule source."""

    coverage = {
        source: sorted(set(ttps)) for source, ttps in PARSER_TTP_COVERAGE.items()
    }
    builtin = _builtin_ttp_coverage()
    coverage["rules.json"] = builtin["finding_rules"]
    coverage["port_rules"] = builtin["port_rules"]
    coverage["chains"] = builtin["chains"]
    return dict(sorted(coverage.items()))


def coverage_gaps() -> list[str]:
    """Return high-value TTPs that are not covered by known rules."""

    return sorted(ALL_HIGH_VALUE - _all_known_ttps())


def coverage_summary() -> dict[str, object]:
    """Return aggregate ATT&CK coverage counters for CLI/reporting."""

    known = sorted(_all_known_ttps())
    gaps = coverage_gaps()
    return {
        "known_ttps": known,
        "unique_count": len(known),
        "attack_total": ATTACK_ENTERPRISE_TOTAL,
        "coverage_percent": round((len(known) / ATTACK_ENTERPRISE_TOTAL) * 100, 1),
        "gaps": gaps,
        "gap_details": [
            (technique_id, technique_name(technique_id)) for technique_id in gaps
        ],
    }


def technique_name(technique_id: str) -> str:
    """Return a technique name from bundled data or high-value fallbacks."""

    for item in _load_attack_db().get("techniques", []):
        if item.get("id") == technique_id:
            return str(item.get("name") or technique_id)
    for item in _load_attack_db().get("objects", []):
        references = item.get("external_references", [])
        if any(
            reference.get("external_id") == technique_id for reference in references
        ):
            return str(item.get("name") or technique_id)
    return TECHNIQUE_NAME_FALLBACKS.get(technique_id, technique_id)


def _all_known_ttps() -> set[str]:
    coverage = tool_ttp_coverage()
    return {technique_id for values in coverage.values() for technique_id in values}


def _discovered_ttps(findings: list[Finding]) -> set[str]:
    return {
        match.technique_id for finding in findings for match in finding.mitre_matches
    }


def _tactic_techniques() -> dict[str, list[str]]:
    grouped: dict[str, set[str]] = {}
    for technique_id, tactics in _technique_tactics().items():
        for tactic in tactics:
            grouped.setdefault(tactic, set()).add(technique_id)
    return {
        tactic: sorted(techniques) for tactic, techniques in sorted(grouped.items())
    }


def _technique_tactics() -> dict[str, list[str]]:
    mapping: dict[str, set[str]] = {}
    db = _load_attack_db()

    for item in db.get("techniques", []):
        technique_id = item.get("id")
        tactic = item.get("tactic")
        if technique_id and tactic:
            mapping.setdefault(str(technique_id), set()).add(str(tactic))

    for item in db.get("objects", []):
        if item.get("type") != "attack-pattern":
            continue
        technique_id = _external_technique_id(item)
        if not technique_id:
            continue
        for phase in item.get("kill_chain_phases", []):
            phase_name = phase.get("phase_name")
            if phase_name:
                mapping.setdefault(technique_id, set()).add(
                    _format_tactic_name(str(phase_name))
                )

    return {technique_id: sorted(tactics) for technique_id, tactics in mapping.items()}


def _external_technique_id(item: dict[str, object]) -> str | None:
    for reference in item.get("external_references", []):
        if not isinstance(reference, dict):
            continue
        external_id = reference.get("external_id")
        if isinstance(external_id, str) and external_id.startswith("T"):
            return external_id
    return None


def _format_tactic_name(phase_name: str) -> str:
    return phase_name.replace("-", " ").title()


def _load_rules_json() -> dict[str, list[str]]:
    path = resources.files("pentnote.mitre.data").joinpath("rules.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _load_chain_json() -> dict[str, dict[str, list[str]]]:
    path = resources.files("pentnote.mitre.data").joinpath("chains.json")
    return json.loads(path.read_text(encoding="utf-8"))
