from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from click.testing import CliRunner
from pentnote.cli import main
from pentnote.core.engagement import (
    find_engagement_root,
    init_engagement,
    load_engagement,
    load_findings,
    maybe_load_engagement,
    merge_and_save_findings,
    save_engagement_config,
    save_findings,
)
from pentnote.core.init_engine import ensure_operator_gitignore
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


def test_save_engagement_config_write_survives_mid_write_failure(
    tmp_path: Path, monkeypatch
) -> None:
    engagement = init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    original = engagement.config_path.read_text(encoding="utf-8")

    def boom_replace(src, dst):
        raise OSError("simulated crash mid-write")

    monkeypatch.setattr(os, "replace", boom_replace)

    with pytest.raises(OSError):
        save_engagement_config(engagement)

    assert engagement.config_path.read_text(encoding="utf-8") == original
    assert list(engagement.config_path.parent.glob("*.tmp")) == []


def test_save_engagement_config_write_uses_same_directory_temp_file(
    tmp_path: Path, monkeypatch
) -> None:
    engagement = init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    seen: dict[str, Path] = {}
    real_replace = os.replace

    def spy_replace(src, dst):
        seen["tmp_parent"] = Path(src).parent
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)

    save_engagement_config(engagement)

    assert seen["tmp_parent"] == engagement.config_path.parent


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_save_engagement_config_write_preserves_permissions(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    os.chmod(engagement.config_path, 0o640)

    save_engagement_config(engagement)

    assert stat.S_IMODE(engagement.config_path.stat().st_mode) == 0o640


def test_save_findings_write_survives_mid_write_failure(
    tmp_path: Path, monkeypatch
) -> None:
    engagement = init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    save_findings(
        engagement,
        [
            Finding(
                title="Existing",
                severity=Severity.LOW,
                evidence="e",
                hash="existing-hash",
            )
        ],
    )
    original = engagement.findings_path.read_text(encoding="utf-8")

    def boom_replace(src, dst):
        raise OSError("simulated crash mid-write")

    monkeypatch.setattr(os, "replace", boom_replace)

    with pytest.raises(OSError):
        save_findings(engagement, [])

    assert engagement.findings_path.read_text(encoding="utf-8") == original
    assert list(engagement.findings_path.parent.glob("*.tmp")) == []


def test_save_findings_write_uses_same_directory_temp_file(
    tmp_path: Path, monkeypatch
) -> None:
    engagement = init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    seen: dict[str, Path] = {}
    real_replace = os.replace

    def spy_replace(src, dst):
        seen["tmp_parent"] = Path(src).parent
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)

    save_findings(engagement, [])

    assert seen["tmp_parent"] == engagement.findings_path.parent


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_save_findings_write_preserves_permissions(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    os.chmod(engagement.findings_path, 0o640)

    save_findings(engagement, [])

    assert stat.S_IMODE(engagement.findings_path.stat().st_mode) == 0o640


def test_gitignore_write_survives_mid_write_failure(
    tmp_path: Path, monkeypatch
) -> None:
    init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    gitignore_path = tmp_path / ".gitignore"
    # Drop an entry so ensure_operator_gitignore has something to re-add and
    # therefore actually reaches the write path below.
    stripped = (
        "\n".join(
            line
            for line in gitignore_path.read_text(encoding="utf-8").splitlines()
            if line != ".pentnote/local.json"
        )
        + "\n"
    )
    gitignore_path.write_text(stripped, encoding="utf-8")

    def boom_replace(src, dst):
        raise OSError("simulated crash mid-write")

    monkeypatch.setattr(os, "replace", boom_replace)

    with pytest.raises(OSError):
        ensure_operator_gitignore(tmp_path)

    assert gitignore_path.read_text(encoding="utf-8") == stripped
    assert list(gitignore_path.parent.glob("*.tmp")) == []


def test_gitignore_write_uses_same_directory_temp_file(
    tmp_path: Path, monkeypatch
) -> None:
    init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    gitignore_path = tmp_path / ".gitignore"
    gitignore_path.write_text("custom-entry\n", encoding="utf-8")
    seen: dict[str, Path] = {}
    real_replace = os.replace

    def spy_replace(src, dst):
        seen["tmp_parent"] = Path(src).parent
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)

    ensure_operator_gitignore(tmp_path)

    assert seen["tmp_parent"] == gitignore_path.parent


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_gitignore_write_preserves_permissions(tmp_path: Path) -> None:
    init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])
    gitignore_path = tmp_path / ".gitignore"
    # Drop an entry so ensure_operator_gitignore actually rewrites the file.
    stripped = (
        "\n".join(
            line
            for line in gitignore_path.read_text(encoding="utf-8").splitlines()
            if line != ".pentnote/local.json"
        )
        + "\n"
    )
    gitignore_path.write_text(stripped, encoding="utf-8")
    os.chmod(gitignore_path, 0o640)

    ensure_operator_gitignore(tmp_path)

    assert stat.S_IMODE(gitignore_path.stat().st_mode) == 0o640


def test_init_local_json_write_survives_mid_write_failure(
    tmp_path: Path, monkeypatch
) -> None:
    from pentnote.core import init_engine

    real_atomic_write_json = init_engine.atomic_write_json

    def boom(path, value, *args, **kwargs):
        if path.name == "local.json":
            raise OSError("simulated crash mid-write")
        return real_atomic_write_json(path, value, *args, **kwargs)

    monkeypatch.setattr(init_engine, "atomic_write_json", boom)

    with pytest.raises(OSError):
        init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])

    local_path = tmp_path / ".pentnote" / "local.json"
    assert not local_path.exists()
    assert list(local_path.parent.glob("*.tmp")) == []


def test_init_findings_json_write_survives_mid_write_failure(
    tmp_path: Path, monkeypatch
) -> None:
    from pentnote.core import init_engine

    real_atomic_write_json = init_engine.atomic_write_json

    def boom(path, value, *args, **kwargs):
        if path.name == "findings.json":
            raise OSError("simulated crash mid-write")
        return real_atomic_write_json(path, value, *args, **kwargs)

    monkeypatch.setattr(init_engine, "atomic_write_json", boom)

    with pytest.raises(OSError):
        init_engagement(tmp_path, "Client_2026", ["192.168.56.0/24"])

    findings_path = tmp_path / ".pentnote" / "findings.json"
    assert not findings_path.exists()
    assert list(findings_path.parent.glob("*.tmp")) == []


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
