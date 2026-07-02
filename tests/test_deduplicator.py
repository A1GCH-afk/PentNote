from __future__ import annotations

from pathlib import Path

from pentnote.core.deduplicator import finding_hash, merge_findings
from pentnote.parsers.v1.crackmapexec import CrackMapExecParser

FIXTURES = Path(__file__).parent / "fixtures"


def test_finding_hash_uses_tool_host_title_case_insensitively() -> None:
    assert finding_hash("NMAP", "192.168.56.10", "Open SMB") == finding_hash(
        "nmap",
        "192.168.56.10",
        "open smb",
    )


def test_duplicate_runs_are_idempotent() -> None:
    parser = CrackMapExecParser()
    content = (FIXTURES / "cme_sample.txt").read_text()
    first = parser.parse(content).findings
    second = parser.parse(content).findings

    result = merge_findings(first, second)

    assert [finding.hash for finding in first] == [finding.hash for finding in second]
    assert result.new == []
    assert result.duplicates == second
