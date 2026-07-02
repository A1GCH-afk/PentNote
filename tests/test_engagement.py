from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from pentnote.cli import main
from pentnote.core.engagement import (
    find_engagement_root,
    init_engagement,
    load_engagement,
    load_findings,
    maybe_load_engagement,
    merge_and_save_findings,
)
from pentnote.core.models import EngagementType, Finding, Severity, TargetGroup
from pentnote.generators.markdown import _assign_target_group, write_result_markdown
from pentnote.generators.report import write_report
from pentnote.parsers.v1.crackmapexec import CrackMapExecParser
from pentnote.sync.ignore import warn_if_sensitive_paths_not_ignored

FIXTURES = Path(__file__).parent / "fixtures"


def test_engagement_creation_discovery_and_persistence(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    nested = tmp_path / "notes" / "nested"
    nested.mkdir(parents=True)

    assert engagement.config_path.exists()
    assert find_engagement_root(nested) == tmp_path
    assert maybe_load_engagement(tmp_path) == load_engagement(tmp_path)

    result = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())
    write_result_markdown(result, engagement.notes_dir, engagement_name=engagement.name)
    new, duplicates = merge_and_save_findings(engagement, result.findings)
    assert len(new) == len(result.findings)
    assert duplicates == []
    new_again, duplicates_again = merge_and_save_findings(engagement, result.findings)
    assert new_again == []
    assert len(duplicates_again) == len(result.findings)
    assert load_findings(engagement)


def test_init_writes_opsec_gitignore_and_local_template(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])

    gitignore = (tmp_path / ".gitignore").read_text(encoding="utf-8").splitlines()
    for entry in (
        ".pentnote/local.json",
        ".pentnote/workspace.json",
        ".pentnote/*.lock",
        ".pentnote/*.pid",
        ".pentnote/*.tmp",
        ".pentnote/ghostlog-*.jsonl",
        "*.log",
        "__pycache__/",
    ):
        assert entry in gitignore
        assert gitignore.count(entry) == 1

    json.loads(engagement.local_config_path.read_text(encoding="utf-8"))
    example = engagement.state_dir / "local.example.jsonc"
    assert example.exists()
    assert "operator-specific secrets" in example.read_text(encoding="utf-8").casefold()


def test_init_writes_gitignore_with_local_json(tmp_path: Path) -> None:
    init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])

    gitignore = (tmp_path / ".gitignore").read_text(encoding="utf-8")

    assert ".pentnote/local.json" in gitignore


def test_init_does_not_duplicate_gitignore_entries(tmp_path: Path) -> None:
    init_engagement(tmp_path, "Client_2026", [])
    init_engagement(tmp_path, "Client_2026", [])

    gitignore = (tmp_path / ".gitignore").read_text(encoding="utf-8").splitlines()

    assert gitignore.count(".pentnote/local.json") == 1
    assert gitignore.count(".pentnote/workspace.json") == 1


def test_sync_warns_if_local_json_not_ignored(tmp_path: Path, capsys) -> None:
    init_engagement(tmp_path, "Client_2026", [])
    (tmp_path / ".gitignore").write_text(".pentnote/workspace.json\n", encoding="utf-8")

    missing = warn_if_sensitive_paths_not_ignored(tmp_path)
    captured = capsys.readouterr()

    assert missing == [".pentnote/local.json"]
    assert "local.json not in .gitignore" in captured.err


def test_doctor_flags_missing_gitignore_entry(tmp_path: Path) -> None:
    init_engagement(tmp_path, "Client_2026", [])
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text(
        "\n".join(
            line
            for line in gitignore.read_text(encoding="utf-8").splitlines()
            if line != ".pentnote/local.json"
        )
        + "\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(main, ["status", "--health", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (
        "[!] local.json not in .gitignore — run pentnote status --health --fix"
        in result.output
    )


def test_wizard_stores_client_name(tmp_path: Path) -> None:
    cwd, result = _run_init_wizard(tmp_path)

    config = json.loads(
        (Path(cwd) / "WingData" / ".pentnote" / "config.json").read_text(
            encoding="utf-8"
        )
    )

    assert result.exit_code == 0, result.output
    assert config["client_name"] == "ACME Corporation"


def test_wizard_stores_engagement_type(tmp_path: Path) -> None:
    cwd, result = _run_init_wizard(tmp_path)

    config = json.loads(
        (Path(cwd) / "WingData" / ".pentnote" / "config.json").read_text(
            encoding="utf-8"
        )
    )

    assert result.exit_code == 0, result.output
    assert config["engagement_type"] == "internal-ad"
    assert config["scope"] == ["192.168.56.0/24", "north.local"]
    assert config["operator"] == "operator1"


def test_config_engagement_type_enum_valid() -> None:
    assert EngagementType("internal-ad") == EngagementType.INTERNAL_AD
    assert EngagementType("assumed-breach") == EngagementType.ASSUMED_BREACH


def test_report_includes_client_name(tmp_path: Path) -> None:
    engagement = init_engagement(
        tmp_path,
        "WingData",
        ["192.168.56.0/24"],
        client_name="ACME Corporation",
        engagement_type=EngagementType.INTERNAL_AD,
        start_date="2026-05-03",
        operator="operator1",
    )

    paths = write_report(
        [],
        engagement.reports_dir,
        engagement_name=engagement.name,
        engagement=engagement,
    )

    assert "Client:** ACME Corporation" in paths[0].read_text(encoding="utf-8")


def test_report_includes_engagement_type(tmp_path: Path) -> None:
    engagement = init_engagement(
        tmp_path,
        "WingData",
        ["192.168.56.0/24"],
        client_name="ACME Corporation",
        engagement_type=EngagementType.INTERNAL_AD,
        start_date="2026-05-03",
    )

    paths = write_report(
        [],
        engagement.reports_dir,
        engagement_name=engagement.name,
        engagement=engagement,
    )
    report_text = paths[0].read_text(encoding="utf-8")

    assert "Engagement type:** Internal Active Directory" in report_text
    assert "Start date:** May 3, 2026" in report_text


def test_status_shows_engagement_type(tmp_path: Path) -> None:
    init_engagement(
        tmp_path,
        "WingData",
        ["192.168.56.0/24", "north.local"],
        client_name="ACME Corporation",
        engagement_type=EngagementType.INTERNAL_AD,
    )

    result = CliRunner().invoke(main, ["status", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "Internal AD" in result.output
    assert "ACME Corporation" in result.output


def test_target_group_created_in_config(tmp_path: Path) -> None:
    init_engagement(tmp_path, "WingData", ["192.168.56.0/24"])

    result = CliRunner().invoke(
        main,
        [
            "targets",
            "add",
            "Cloud",
            "--scope",
            "172.16.0.0/24",
            "--vault",
            str(tmp_path),
        ],
    )
    config = json.loads((tmp_path / ".pentnote" / "config.json").read_text())

    assert result.exit_code == 0, result.output
    assert config["target_groups"] == [
        {"name": "Cloud", "scope": ["172.16.0.0/24"], "description": ""}
    ]


def test_target_group_ip_assignment() -> None:
    groups = [TargetGroup(name="DMZ", scope=["10.10.10.15"])]

    assert _assign_target_group("10.10.10.15", groups) == "DMZ"


def test_target_group_cidr_assignment() -> None:
    groups = [TargetGroup(name="Internal", scope=["192.168.1.0/24"])]

    assert _assign_target_group("192.168.1.55", groups) == "Internal"


def test_target_group_domain_assignment() -> None:
    groups = [TargetGroup(name="AD", scope=["north.local"])]

    assert _assign_target_group("dc01.north.local", groups) == "AD"


def test_report_groups_findings_by_target(tmp_path: Path) -> None:
    engagement = init_engagement(
        tmp_path,
        "WingData",
        ["10.10.10.0/24", "192.168.56.0/24"],
        target_groups=[
            TargetGroup(name="DMZ", scope=["10.10.10.0/24"]),
            TargetGroup(name="AD", scope=["192.168.56.0/24"]),
        ],
    )
    findings = [
        _target_finding("Public Web Finding", "10.10.10.15"),
        _target_finding("Domain Finding", "192.168.56.11"),
    ]

    paths = write_report(
        findings,
        engagement.reports_dir,
        engagement_name=engagement.name,
        engagement=engagement,
    )
    report = paths[0].read_text(encoding="utf-8")

    assert "### DMZ Findings (10.10.10.0/24)" in report
    assert "| High | Public Web Finding | 10.10.10.15 |" in report
    assert "### AD Findings (192.168.56.0/24)" in report


def test_targets_list_shows_finding_counts(tmp_path: Path) -> None:
    engagement = init_engagement(
        tmp_path,
        "WingData",
        ["10.10.10.0/24"],
        target_groups=[TargetGroup(name="DMZ", scope=["10.10.10.0/24"])],
    )
    merge_and_save_findings(
        engagement,
        [
            _target_finding("Public Web Finding", "10.10.10.15"),
            _target_finding("Another DMZ Finding", "10.10.10.20"),
        ],
    )

    result = CliRunner().invoke(main, ["targets", "list", "--vault", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "DMZ" in result.output
    assert "findings: 2" in result.output


def test_targets_list_counts_hosts_from_host_notes(tmp_path: Path) -> None:
    init_engagement(
        tmp_path,
        "WingData",
        ["192.168.56.0/24"],
        target_groups=[TargetGroup(name="AD", scope=["192.168.56.0/24"])],
    )
    host_dir = tmp_path / "notes" / "hosts"
    host_dir.mkdir(parents=True)
    (host_dir / "192-168-56-11.md").write_text(
        "\n".join(
            [
                "---",
                "host: 192.168.56.11",
                "hostname: winterfell",
                "---",
                "# winterfell",
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(main, ["targets", "list", "--vault", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "AD" in result.output
    assert "hosts: 1" in result.output


def test_targets_show_counts_hosts_from_host_notes(tmp_path: Path) -> None:
    init_engagement(
        tmp_path,
        "WingData",
        ["192.168.56.0/24"],
        target_groups=[TargetGroup(name="AD", scope=["winterfell"])],
    )
    host_dir = tmp_path / "notes" / "hosts"
    host_dir.mkdir(parents=True)
    (host_dir / "192-168-56-11.md").write_text(
        "\n".join(
            [
                "---",
                "host: 192.168.56.11",
                "hostname: winterfell",
                "---",
                "# winterfell",
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main, ["targets", "show", "AD", "--vault", str(tmp_path)]
    )

    assert result.exit_code == 0, result.output
    assert "Hosts: 1" in result.output


def _target_finding(title: str, host: str) -> Finding:
    return Finding(
        title=title,
        severity=Severity.HIGH,
        affected_hosts=[host],
        evidence=title,
        hash=f"target-{title.casefold().replace(' ', '-')}",
    )


def _run_init_wizard(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path) as cwd:
        result = runner.invoke(
            main,
            ["init", "--wizard"],
            input=(
                "WingData\n"
                "ACME Corporation\n"
                "1\n"
                "192.168.56.0/24\n"
                "north.local\n"
                "\n"
                "operator1\n"
                "Q2 2026 internal AD assessment\n"
            ),
        )
        return cwd, result
