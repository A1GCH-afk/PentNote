from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

from click.testing import CliRunner
from pentnote.cli import main
from pentnote.core.engagement import init_engagement, save_findings
from pentnote.generators.markdown import write_result_markdown
from pentnote.generators.report import write_report
from pentnote.mitre.chain_detector import detect_chains
from pentnote.mitre.classifier import (
    PORT_MITRE_RULES,
    MitreClassifier,
    _load_attack_db,
    classify_host_ports,
    default_attack_db_path,
)
from pentnote.mitre.coverage import (
    _tactic_coverage,
    coverage_gaps,
    coverage_summary,
    format_coverage_output,
    tactic_coverage,
    technique_name,
)
from pentnote.mitre.defends import DEFENDS_MAP, defenses_for_matches
from pentnote.mitre.navigator import export_navigator_layer
from pentnote.mitre.next_steps import (
    get_contextual_next_steps,
    next_steps_for_host,
    suggest_next_steps,
)
from pentnote.mitre.scorer import score_finding, severity_for_host
from pentnote.models import (
    Finding,
    Host,
    MitreMatch,
    ParsedResult,
    Port,
    Severity,
    WorkspaceCredential,
)


def _rules_json() -> dict[str, list[str]]:
    path = resources.files("pentnote.mitre.data").joinpath("rules.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _host_with_ports(*ports: int) -> Host:
    return Host(
        ip="10.129.48.183",
        hostname="wingdata.htb",
        os="Linux",
        ports=[
            Port(
                number=port,
                protocol="tcp",
                service={22: "ssh", 80: "http", 445: "microsoft-ds"}.get(
                    port, "unknown"
                ),
                version={22: "OpenSSH 9.2p1", 80: "Apache httpd 2.4.66"}.get(port),
                state="open",
            )
            for port in ports
        ],
        tags=[],
    )


def _finding_with_ttp(title: str, severity: Severity, technique_id: str) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[
            MitreMatch(
                technique_id,
                technique_id,
                "Lateral Movement",
                1.0,
                "rule",
            )
        ],
        affected_hosts=["10.0.0.1"],
        evidence=title,
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash=title.casefold().replace(" ", "-"),
    )


def test_classifier_rule_and_keyword_layers() -> None:
    classifier = MitreClassifier(default_attack_db_path())

    rule = classifier.classify("SMB signing disabled", "signing not required")
    keyword = classifier.classify("Unknown issue", "nmap network service discovery")

    assert rule[0].technique_id == "T1557.001"
    assert rule[0].confidence == 1.0
    assert any(match.technique_id == "T1046" for match in keyword)


def test_rules_json_has_no_typos() -> None:
    rules = _rules_json()

    assert "ntml_relay" not in rules
    assert "ntlm_relay" in rules


def test_rules_json_all_ttps_valid_format() -> None:
    technique_id = re.compile(r"^T\d{4}(?:\.\d{3})?$")

    assert all(
        technique_id.fullmatch(value)
        for values in _rules_json().values()
        for value in values
    )


def test_new_rules_password_spraying() -> None:
    assert _rules_json()["password_spraying"] == ["T1110.003"]


def test_new_rules_adcs_esc() -> None:
    rules = _rules_json()

    assert rules["adcs_esc1"] == ["T1649"]
    assert rules["adcs_esc8"] == ["T1649", "T1557.001"]


def test_coverage_tool_flag_shows_per_parser_ttps() -> None:
    result = CliRunner().invoke(main, ["mitre", "coverage", "--tool"])

    assert result.exit_code == 0, result.output
    assert "nmap" in result.output
    assert "crackmapexec" in result.output
    assert "rules.json" in result.output
    assert "Total unique TTPs:" in result.output


def test_rules_json_persistence_coverage() -> None:
    rules = _rules_json()

    assert rules["scheduled_task"] == ["T1053.005"]
    assert rules["service_creation"] == ["T1543.003"]
    assert rules["web_shell"] == ["T1505.003"]


def test_rules_json_execution_coverage() -> None:
    rules = _rules_json()

    assert rules["powershell_exec"] == ["T1059.001"]
    assert rules["cmd_exec"] == ["T1059.003"]
    assert rules["wmi_exec"] == ["T1047"]


def test_rules_json_defense_evasion_coverage() -> None:
    rules = _rules_json()

    assert rules["amsi_bypass"] == ["T1562.001"]
    assert rules["log_cleared"] == ["T1070.001"]
    assert rules["obfuscated_command"] == ["T1027"]


def test_rules_json_c2_coverage() -> None:
    rules = _rules_json()

    assert rules["c2_http_beacon"] == ["T1071.001"]
    assert rules["socks_proxy"] == ["T1090.003"]
    assert rules["chisel_tunnel"] == ["T1572"]


def test_rules_json_c2_http_maps_t1071_001() -> None:
    assert _rules_json()["c2_http"] == ["T1071.001"]


def test_rules_json_rclone_maps_t1567_002() -> None:
    assert _rules_json()["rclone_upload"] == ["T1567.002"]


def test_rules_json_chisel_maps_t1572() -> None:
    assert _rules_json()["chisel_tunnel"] == ["T1572"]


def test_coverage_gaps_returns_missing_high_value_ttps() -> None:
    gaps = coverage_gaps()

    assert gaps == ["T1567"]


def test_coverage_tool_shows_per_parser_count() -> None:
    result = CliRunner().invoke(main, ["mitre", "coverage", "--tool"])

    assert result.exit_code == 0, result.output
    assert "nmap" in result.output
    assert "TTPs)" in result.output
    assert "ATT&CK total: 196 techniques" in result.output
    assert "Coverage gaps (high-value TTPs not covered):" in result.output


def test_total_ttp_count_above_60_after_expansion() -> None:
    assert coverage_summary()["unique_count"] > 60


def test_total_ttp_count_above_118() -> None:
    assert coverage_summary()["unique_count"] >= 118


def test_rules_json_persistence_sub_techniques() -> None:
    rules = _rules_json()

    assert rules["at_job"] == ["T1053.002"]
    assert rules["screensaver_hijack"] == ["T1546.002"]
    assert rules["create_account_domain"] == ["T1136.002"]


def test_rules_json_privesc_sub_techniques() -> None:
    rules = _rules_json()

    assert rules["token_impersonation"] == ["T1134.001"]
    assert rules["dll_sideloading"] == ["T1574.002"]
    assert rules["ptrace_injection"] == ["T1055.008"]


def test_rules_json_defense_evasion_sub_techniques() -> None:
    rules = _rules_json()

    assert rules["clear_linux_logs"] == ["T1070.002"]
    assert rules["base64_encoding"] == ["T1027.010"]
    assert rules["process_doppelganging"] == ["T1055.013"]


def test_rules_json_execution_sub_techniques() -> None:
    rules = _rules_json()

    assert rules["python_script"] == ["T1059.006"]
    assert rules["cmstp"] == ["T1218.003"]
    assert rules["user_exec_malicious_link"] == ["T1204.001"]


def test_linux_privesc_chain_detected() -> None:
    chains = detect_chains(
        [
            _finding_with_ttp("SUID", Severity.HIGH, "T1548.001"),
            _finding_with_ttp("Sudo", Severity.CRITICAL, "T1548.003"),
            _finding_with_ttp("Shadow", Severity.CRITICAL, "T1003.008"),
        ]
    )

    assert any(chain.name == "linux_privesc_chain" for chain in chains)


def test_windows_privesc_chain_detected() -> None:
    chains = detect_chains(
        [
            _finding_with_ttp("UAC", Severity.HIGH, "T1548.002"),
            _finding_with_ttp("DLL Search", Severity.HIGH, "T1574.001"),
            _finding_with_ttp("SAM", Severity.CRITICAL, "T1003.002"),
        ]
    )

    assert any(chain.name == "windows_privesc_chain" for chain in chains)


def test_persistence_chain_detected() -> None:
    chains = detect_chains(
        [
            _finding_with_ttp("Run Key", Severity.HIGH, "T1547.001"),
            _finding_with_ttp("Local Account", Severity.HIGH, "T1136.001"),
            _finding_with_ttp("Account Manipulation", Severity.HIGH, "T1098"),
        ]
    )

    assert any(chain.name == "persistence_chain" for chain in chains)


def test_coverage_summary_reports_enterprise_total() -> None:
    summary = coverage_summary()

    assert summary["attack_total"] == 196
    assert summary["coverage_percent"] > 40.0


def test_coverage_gap_names_use_high_value_fallbacks() -> None:
    assert technique_name("T1567") == "Exfiltration Over Web Service"


def test_attack_db_loads_from_package() -> None:
    path = default_attack_db_path()

    assert path.parts[-4:] == ("pentnote", "mitre", "data", "enterprise-attack.json")
    assert path.exists()


def test_attack_db_contains_expected_techniques() -> None:
    data = _load_attack_db()
    if "techniques" in data:
        techniques = {item["id"] for item in data["techniques"]}
    else:
        techniques = {
            reference["external_id"]
            for item in data["objects"]
            if item.get("type") == "attack-pattern"
            for reference in item.get("external_references", [])
            if reference.get("external_id")
        }

    assert {"T1046", "T1021.002"} <= techniques


def test_attack_db_not_loaded_from_data_directory() -> None:
    repo_data_copy = Path(__file__).resolve().parents[1] / "data" / "mitre"

    assert not (repo_data_copy / "enterprise-attack.json").exists()
    path_parts = default_attack_db_path().parts
    assert ("data", "mitre") not in zip(path_parts, path_parts[1:], strict=False)


def test_navigator_export_is_valid_json() -> None:
    finding = Finding(
        "Open SMB",
        Severity.HIGH,
        [
            MitreMatch(
                "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", 1.0, "rule"
            )
        ],
        ["192.168.56.10"],
        "445/tcp",
        [],
        [],
        None,
        "hash",
    )

    layer = export_navigator_layer([finding])

    assert json.loads(json.dumps(layer))["domain"] == "enterprise-attack"
    assert layer["techniques"][0]["techniqueID"] == "T1021.002"


def test_tactic_coverage_returns_percentages() -> None:
    finding = Finding(
        "Open SMB",
        Severity.HIGH,
        [
            MitreMatch(
                "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", 1.0, "rule"
            )
        ],
        ["192.168.56.10"],
        "445/tcp",
        [],
        [],
        None,
        "hash",
    )

    coverage = tactic_coverage([finding])

    assert "Lateral Movement" in coverage
    assert coverage["Lateral Movement"] > 0


def test_coverage_counts_sub_technique_as_parent_covered() -> None:
    discovered = {"T1021.002", "T1550.002"}

    coverage = _tactic_coverage(["T1021", "T1021.001", "T1021.002"], discovered)

    assert coverage > 0.3


def test_coverage_sub_technique_directly_counts() -> None:
    discovered = {"T1021.002"}

    coverage = _tactic_coverage(["T1021.002"], discovered)

    assert coverage == 1.0


def test_lateral_movement_not_zero_with_smb_finding() -> None:
    discovered = {"T1021.002", "T1550.002"}
    lm_techniques = [
        "T1210",
        "T1534",
        "T1570",
        "T1021",
        "T1021.001",
        "T1021.002",
        "T1550",
        "T1550.002",
        "T1091",
    ]

    coverage = _tactic_coverage(lm_techniques, discovered)

    assert coverage > 0.15


def test_coverage_format_shows_discovered_count() -> None:
    output = format_coverage_output(
        {"Lateral Movement": 0.025},
        {"Lateral Movement": ["T1021.002", "T1550.002"]},
        {"Lateral Movement": 80},
    )

    assert "2/80" in output[0]
    assert "(2 found)" in output[0]


def test_coverage_format_checkmark_when_discovered() -> None:
    output = format_coverage_output(
        {"Credential Access": 0.72},
        {"Credential Access": ["T1003.001"]},
        {"Credential Access": 80},
    )

    assert "✓" in output[0]


def test_coverage_format_no_checkmark_when_empty() -> None:
    output = format_coverage_output(
        {"Reconnaissance": 0.0},
        {"Reconnaissance": []},
        {"Reconnaissance": 10},
    )

    assert "✓" not in output[0]


def test_coverage_engagement_flag_hides_zero_tactics(
    tmp_path: Path,
    monkeypatch,
) -> None:
    engagement = init_engagement(
        root=tmp_path,
        name="CoverageLab",
        scope=["10.0.0.0/24"],
    )
    save_findings(
        engagement,
        [_finding_with_ttp("Open SMB", Severity.HIGH, "T1021.002")],
    )
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["mitre", "coverage", "--engagement"])

    assert result.exit_code == 0, result.output
    assert "Lateral Movement" in result.output
    assert "Reconnaissance" not in result.output


def test_next_steps_and_defenses_are_mapped() -> None:
    matches = [
        MitreMatch(
            "T1557.001",
            "LLMNR/NBT-NS Poisoning and SMB Relay",
            "Credential Access",
            1.0,
            "rule",
        )
    ]

    assert suggest_next_steps(matches)
    assert defenses_for_matches(matches)


def test_contextual_next_steps_uses_real_host() -> None:
    creds = [
        WorkspaceCredential(
            username="brandon.stark",
            secret="HASHVALUE",
            secret_type="ntlm",
            source_host="192.168.56.11",
        )
    ]

    steps = get_contextual_next_steps(["T1550.002"], [], creds, ["192.168.56.11"])

    assert any("192.168.56.11" in step for step in steps)
    assert any("brandon.stark" in step for step in steps)


def test_contextual_next_steps_ntlm_uses_hash_flag() -> None:
    creds = [
        WorkspaceCredential(
            username="admin",
            secret="HASH",
            secret_type="ntlm",
            source_host="10.0.0.1",
        )
    ]

    steps = get_contextual_next_steps(["T1550.002"], [], creds, ["10.0.0.1"])

    assert any("-H" in step for step in steps)
    assert not any("-p" in step for step in steps)


def test_contextual_next_steps_plaintext_uses_password_flag() -> None:
    creds = [
        WorkspaceCredential(
            username="admin",
            secret="P@ssw0rd",
            secret_type="plaintext",
            source_host="10.0.0.1",
        )
    ]

    steps = get_contextual_next_steps(["T1550.002"], [], creds, ["10.0.0.1"])

    assert any("-p" in step for step in steps)
    assert not any("-H" in step for step in steps)
    assert not any("P@ssw0rd" in step for step in steps)


def test_contextual_next_steps_no_creds_uses_placeholder() -> None:
    steps = get_contextual_next_steps(["T1550.002"], [], [], ["10.0.0.1"])

    assert any("{PASS}" in step or "{USER}" in step for step in steps)


def test_contextual_next_steps_kerberoast() -> None:
    steps = get_contextual_next_steps(["T1558.003"], [], [], [])

    assert any("hashcat" in step and "13100" in step for step in steps)


def test_contextual_next_steps_smb_relay() -> None:
    steps = get_contextual_next_steps(["T1557.001"], [], [], ["10.0.0.1"])

    assert any("responder" in step.lower() for step in steps)
    assert any("ntlmrelayx" in step.lower() for step in steps)


def test_host_severity_dc_is_critical() -> None:
    assert severity_for_host(_host_with_ports(88, 389, 445)) == Severity.CRITICAL


def test_host_severity_ssh_http_is_medium() -> None:
    assert severity_for_host(_host_with_ports(22, 80)) == Severity.MEDIUM


def test_risk_score_critical_finding_highest() -> None:
    critical = score_finding(_finding_with_ttp("Critical", Severity.CRITICAL, "T1046"))
    low = score_finding(_finding_with_ttp("Low", Severity.LOW, "T1046"))

    assert critical.total > low.total
    assert critical.total <= 5.0


def test_risk_score_chain_member_gets_bonus() -> None:
    finding = _finding_with_ttp("Kerberoastable", Severity.HIGH, "T1558.003")

    without_chain = score_finding(finding, in_chain=False)
    with_chain = score_finding(finding, in_chain=True)

    assert with_chain.total > without_chain.total
    assert with_chain.chain_bonus == 0.5


def test_risk_score_easy_exploit_ttp_increases_score() -> None:
    easy = score_finding(_finding_with_ttp("ASREP", Severity.MEDIUM, "T1558.004"))
    normal = score_finding(_finding_with_ttp("Normal", Severity.MEDIUM, "T1046"))

    assert easy.exploitability > normal.exploitability
    assert easy.total > normal.total


def test_risk_score_lateral_ttp_increases_score() -> None:
    lateral = score_finding(_finding_with_ttp("SMB", Severity.MEDIUM, "T1021.002"))
    normal = score_finding(_finding_with_ttp("Normal", Severity.MEDIUM, "T1046"))

    assert lateral.lateral_potential > normal.lateral_potential
    assert lateral.total > normal.total


def test_report_sorts_by_risk_score_not_severity_only(tmp_path: Path) -> None:
    high_chain = _finding_with_ttp("High Chain", Severity.HIGH, "T1558.003")
    high_chain.chain_member = "Credential Access Chain"
    critical = _finding_with_ttp("Critical Standalone", Severity.CRITICAL, "T1046")

    path = write_report(
        [critical, high_chain],
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
    )[0]
    report = path.read_text(encoding="utf-8")

    assert report.index("### High Chain") < report.index("### Critical Standalone")


def test_report_top_risks_table_has_risk_score_column(tmp_path: Path) -> None:
    path = write_report(
        [_finding_with_ttp("SMB Relay", Severity.HIGH, "T1557.001")],
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
    )[0]

    report = path.read_text(encoding="utf-8")

    assert "| # | Finding | Severity | Risk Score | Exploitability |" in report
    assert "| 1 | SMB Relay | High |" in report


def test_port_mitre_mapping_ssh() -> None:
    matches = classify_host_ports(_host_with_ports(22))

    ssh = next(match for match in matches if match.technique_id == "T1021.004")
    assert ssh.confidence >= 0.9


def test_port_mitre_mapping_smb() -> None:
    technique_ids = {
        match.technique_id for match in classify_host_ports(_host_with_ports(445))
    }

    assert {"T1557.001", "T1021.002"} <= technique_ids


def test_always_add_t1046() -> None:
    technique_ids = {
        match.technique_id for match in classify_host_ports(_host_with_ports(22))
    }

    assert "T1046" in technique_ids


def test_next_steps_ssh() -> None:
    steps = next_steps_for_host(_host_with_ports(22))

    assert any("weak/default credentials" in step for step in steps)


def test_next_steps_http() -> None:
    steps = next_steps_for_host(_host_with_ports(80))

    assert any("gobuster" in step for step in steps)


def test_defends_map_coverage() -> None:
    technique_ids = {
        technique_id
        for rules in PORT_MITRE_RULES.values()
        for technique_id, _, _, _ in rules
    }

    assert technique_ids <= set(DEFENDS_MAP)


def test_host_note_frontmatter_has_severity(tmp_path) -> None:
    note = _write_host_note(tmp_path)

    assert "severity: medium" in note


def test_host_note_has_mitre_section(tmp_path) -> None:
    note = _write_host_note(tmp_path)

    assert "## MITRE ATT&CK Mapping" in note


def test_host_note_has_next_steps(tmp_path) -> None:
    note = _write_host_note(tmp_path)

    assert "## Suggested Next Steps" in note


def test_host_note_has_defends(tmp_path) -> None:
    note = _write_host_note(tmp_path)

    assert "## D3FEND Countermeasures" in note


def _write_host_note(tmp_path) -> str:
    result = ParsedResult(
        tool="nmap",
        partial=False,
        hosts=[_host_with_ports(22, 80)],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )
    write_result_markdown(result, tmp_path)
    return (tmp_path / "hosts" / "10-129-48-183.md").read_text()
