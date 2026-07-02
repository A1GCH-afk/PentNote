from __future__ import annotations

from pentnote.mitre.chain_detector import detect_chains
from pentnote.models import Finding, MitreMatch, Severity


def _finding(technique_id: str) -> Finding:
    return Finding(
        technique_id,
        Severity.HIGH,
        [MitreMatch(technique_id, technique_id, "Credential Access", 1.0, "rule")],
        ["host"],
        technique_id,
        [],
        [],
        None,
        technique_id,
    )


def test_chain_detector_identifies_complete_chain() -> None:
    chains = detect_chains([_finding("T1558.003"), _finding("T1558.004")])

    assert chains[0].name == "kerberos_chain"


def test_chain_detector_does_not_false_positive_partial_chain() -> None:
    assert detect_chains([_finding("T1558.003")]) == []
