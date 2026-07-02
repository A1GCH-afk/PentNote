"""ATT&CK Navigator layer export."""

from __future__ import annotations

import json
from pathlib import Path

from pentnote.models import Finding, Severity


def export_navigator_layer(findings: list[Finding], name: str = "PentNote") -> dict:
    """Build an ATT&CK Navigator layer dictionary."""

    techniques: dict[str, dict[str, object]] = {}
    for finding in findings:
        for match in finding.mitre_matches:
            current = techniques.get(match.technique_id)
            score = _score_for_severity(finding.severity)
            if current is None or score > current["score"]:
                techniques[match.technique_id] = {
                    "techniqueID": match.technique_id,
                    "score": score,
                    "color": _color_for_severity(finding.severity),
                    "comment": finding.title,
                }

    return {
        "name": name,
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "PentNote discovered ATT&CK techniques",
        "techniques": list(techniques.values()),
        "gradient": {
            "colors": ["#f5f5f5", "#fbbf24", "#ef4444"],
            "minValue": 0,
            "maxValue": 100,
        },
    }


def write_navigator_layer(
    findings: list[Finding],
    output_path: Path,
    name: str = "PentNote",
) -> Path:
    """Write an ATT&CK Navigator layer JSON file."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(export_navigator_layer(findings, name), indent=2) + "\n",
        encoding="utf-8",
    )
    return output_path


def _score_for_severity(severity: Severity) -> int:
    return {
        Severity.CRITICAL: 100,
        Severity.HIGH: 80,
        Severity.MEDIUM: 50,
        Severity.LOW: 25,
        Severity.INFO: 10,
    }[severity]


def _color_for_severity(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "#7f1d1d",
        Severity.HIGH: "#dc2626",
        Severity.MEDIUM: "#f97316",
        Severity.LOW: "#facc15",
        Severity.INFO: "#38bdf8",
    }[severity]
