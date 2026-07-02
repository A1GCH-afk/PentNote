from __future__ import annotations

from myparser.parser import MyScannerParser
from pentnote.core.models import ParsedResult

SAMPLE = """[MyScanner] Scan complete
HOST 10.10.10.10 web01 Linux
CRED alice:Password123!@10.10.10.10
VULN 10.10.10.10 Public exploit found
"""


def test_example_parser_can_parse_sample() -> None:
    assert MyScannerParser().can_parse(SAMPLE) == 1.0


def test_example_parser_returns_parsed_result() -> None:
    result = MyScannerParser().parse(SAMPLE)

    assert isinstance(result, ParsedResult)
    assert result.tool == "myscanner"
    assert result.hosts[0].ip == "10.10.10.10"
    assert result.credentials[0].username == "alice"
    assert result.findings[0].mitre_matches[0].technique_id == "T1190"
