from __future__ import annotations

from pathlib import Path

from pentnote.generators.index import write_index
from pentnote.generators.markdown import (
    _credential_path,
    _domain_path,
    _finding_path,
    _short_title,
    render_credential_markdown,
    render_finding_markdown,
    render_host_markdown,
    slugify,
    write_result_markdown,
    write_tool_index,
)
from pentnote.generators.report import (
    _arc_path,
    build_donut_chart_data,
    build_tactic_bars,
    write_report,
)
from pentnote.generators.timeline import write_timeline
from pentnote.mitre.next_steps import get_credential_next_steps
from pentnote.models import (
    Credential,
    DomainObject,
    Finding,
    Host,
    MitreMatch,
    ParsedResult,
    Port,
    Severity,
)
from pentnote.parsers.v1.crackmapexec import CrackMapExecParser
from pentnote.parsers.v1.nmap import NmapParser
from pentnote.parsers.v15.bloodhound import BloodHoundParser

FIXTURES = Path(__file__).parent / "fixtures"


def _sample_finding(
    title: str,
    finding_hash: str = "abc123def456",
) -> Finding:
    return Finding(
        title=title,
        severity=Severity.INFO,
        mitre_matches=[],
        affected_hosts=["kobold.htb"],
        evidence=title,
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash=finding_hash,
    )


def test_render_host_markdown_uses_template_sections() -> None:
    result = NmapParser().parse((FIXTURES / "nmap_sample.xml").read_text())

    markdown = render_host_markdown(
        result.hosts[0],
        engagement_name="Client_2026",
        tool_name="nmap",
        iso_timestamp="2026-04-26T00:00:00+00:00",
    )

    assert "## Target Info" in markdown
    assert "## Open Ports" in markdown
    assert "10.129.48.183" in markdown


def test_write_result_markdown_writes_host_note(tmp_path: Path) -> None:
    result = NmapParser().parse((FIXTURES / "nmap_sample.xml").read_text())

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert written == [tmp_path / "hosts" / "10-129-48-183.md"]
    assert written[0].exists()


def test_write_result_markdown_merges_existing_host_ports(tmp_path: Path) -> None:
    smb = ParsedResult(
        tool="crackmapexec",
        partial=False,
        hosts=[
            Host(
                ip="192.168.56.11",
                hostname="WINTERFELL",
                os="Windows Server 2019 x64",
                ports=[Port(445, "tcp", "smb", None, "open")],
                tags=[],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )
    ldap = ParsedResult(
        tool="crackmapexec",
        partial=False,
        hosts=[
            Host(
                ip="192.168.56.11",
                hostname="WINTERFELL",
                os="Windows Server 2019",
                ports=[Port(389, "tcp", "ldap", None, "open")],
                tags=[],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(smb, tmp_path, engagement_name="Client_2026")
    note_path = tmp_path / "hosts" / "192-168-56-11.md"
    note_path.write_text(
        note_path.read_text() + "\nmanual analyst note\n",
        encoding="utf-8",
    )
    write_result_markdown(ldap, tmp_path, engagement_name="Client_2026")

    note = note_path.read_text()
    assert "| 389 | tcp | ldap | N/A | open |" in note
    assert "| 445 | tcp | smb | N/A | open |" in note
    assert "manual analyst note" in note


def test_write_result_markdown_cross_tool_write_does_not_clobber_prior_tool_data(
    tmp_path: Path,
) -> None:
    """A second tool writing the same host note must not overwrite the first tool's data.

    Root cause: `_merge_existing_host_note` used to rebuild the host's `Host`
    object from scratch, forwarding only `ports`. Every other field --
    `hostname`, `av_products`, and the frontmatter `tool` -- came solely from
    whichever tool ran most recently, silently discarding the previous tool's
    contribution instead of merging it. This reproduces that exact scenario:
    nmap discovers a host under a DNS alias with open ports, then crackmapexec
    resolves its real AD hostname and AV product on the same IP.
    """

    nmap_result = NmapParser().parse((FIXTURES / "nmap_sample.xml").read_text())
    ip = nmap_result.hosts[0].ip
    original_hostname = nmap_result.hosts[0].hostname
    assert original_hostname is not None

    write_result_markdown(nmap_result, tmp_path, engagement_name="Client_2026")
    note_path = tmp_path / "hosts" / f"{ip.replace('.', '-')}.md"

    cme_result = ParsedResult(
        tool="crackmapexec",
        partial=False,
        hosts=[
            Host(
                ip=ip,
                hostname="DC01",
                os="Windows Server 2019 x64",
                ports=[],
                tags=[],
                av_products=["Windows Defender"],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )
    write_result_markdown(cme_result, tmp_path, engagement_name="Client_2026")

    note = note_path.read_text()

    # Both tools are tracked in frontmatter history, not just the last writer.
    assert "tools: [nmap, crackmapexec]" in note
    assert "tool: crackmapexec" in note

    # nmap's Open Ports table survives the crackmapexec write untouched.
    assert "| 22 | tcp | ssh | OpenSSH 9.2p1 Debian 2+deb12u7 | open |" in note
    assert "| 80 | tcp | http | Apache httpd 2.4.66 | open |" in note

    # crackmapexec's AD-resolved hostname wins, but nmap's alias is preserved.
    assert "hostname: DC01" in note
    assert f"| Also Known As | {original_hostname} |" in note

    # crackmapexec's Security Products contribution is present.
    assert "| Windows Defender | Detected |" in note


def test_write_result_markdown_same_tool_rerun_refreshes_its_own_hostname(
    tmp_path: Path,
) -> None:
    """A tool re-running must be able to correct its own previously-reported hostname.

    The hostname-priority rule exists to stop a *different* tool's generic
    alias from clobbering an already-resolved AD hostname. It must not also
    freeze a tool's own value in place: nmap resolving a corrected PTR record
    on a rescan should update the primary hostname, not get permanently
    demoted to an alias behind its own stale first guess.
    """

    ip = "10.6.6.6"
    first = ParsedResult(
        tool="nmap",
        partial=False,
        hosts=[
            Host(
                ip=ip,
                hostname="stale.htb",
                os=None,
                ports=[Port(22, "tcp", "ssh", None, "open")],
                tags=[],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )
    second = ParsedResult(
        tool="nmap",
        partial=False,
        hosts=[
            Host(
                ip=ip,
                hostname="corrected.htb",
                os=None,
                ports=[Port(22, "tcp", "ssh", None, "open")],
                tags=[],
            )
        ],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(first, tmp_path, engagement_name="Client_2026")
    write_result_markdown(second, tmp_path, engagement_name="Client_2026")

    note = (tmp_path / "hosts" / f"{ip.replace('.', '-')}.md").read_text()
    assert "hostname: corrected.htb" in note
    assert "| Also Known As | stale.htb |" in note


def test_write_result_markdown_writes_credentials_findings_and_domain(
    tmp_path: Path,
) -> None:
    cme = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())
    bloodhound = BloodHoundParser().parse(
        (FIXTURES / "bloodhound_sample.json").read_text()
    )

    cme_paths = write_result_markdown(cme, tmp_path, engagement_name="Client_2026")
    domain_paths = write_result_markdown(
        bloodhound,
        tmp_path,
        engagement_name="Client_2026",
    )

    assert any("credentials" in str(path) for path in cme_paths)
    assert any("findings" in str(path) for path in cme_paths)
    assert any("domain" in str(path) for path in domain_paths)


def test_finding_path_uses_tool_subfolder(tmp_path: Path) -> None:
    finding = _sample_finding("Web virtual host discovered: home.kobold.htb")

    path = _finding_path(finding, "gobuster", tmp_path)

    assert path == tmp_path / "findings" / "gobuster" / "home.md"


def test_finding_short_title_removes_tool_prefix() -> None:
    title = "Web virtual host discovered: home page.kobold.htb"

    short = _short_title(title, "gobuster")

    assert "gobuster" not in short
    assert len(short) <= 40


def test_finding_short_title_max_40_chars() -> None:
    title = "A very long finding title that exceeds the limit"

    short = _short_title(title, "nmap")

    assert len(slugify(short)) <= 40


def test_tool_index_created_after_parse(tmp_path: Path) -> None:
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[
            _sample_finding("Web virtual host discovered: home.kobold.htb"),
            _sample_finding("Web virtual host discovered: cgi-bin.kobold.htb"),
        ],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert (tmp_path / "findings" / "gobuster" / "_index.md").exists()


def test_tool_index_contains_all_findings(tmp_path: Path) -> None:
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[
            _sample_finding("Web virtual host discovered: home.kobold.htb"),
            _sample_finding("Web virtual host discovered: cgi-bin.kobold.htb"),
        ],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(result, tmp_path, engagement_name="Client_2026")
    index = (tmp_path / "findings" / "gobuster" / "_index.md").read_text()

    assert "[[home]]" in index
    assert "[[cgi-bin]]" in index


def test_tool_index_written_even_when_no_findings(tmp_path: Path) -> None:
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    index = tmp_path / "findings" / "gobuster" / "_index.md"
    assert index in written
    assert index.exists()


def test_tool_index_empty_shows_success_callout(tmp_path: Path) -> None:
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[],
        domain_objects=[],
        raw_text="",
    )

    write_result_markdown(result, tmp_path, engagement_name="Client_2026")
    index = (tmp_path / "findings" / "gobuster" / "_index.md").read_text()

    assert "[!success] Scan Completed - No Findings" in index


def test_tool_index_nonempty_shows_findings_table(tmp_path: Path) -> None:
    tool_dir = tmp_path / "findings" / "gobuster"
    tool_dir.mkdir(parents=True)
    write_tool_index(
        "gobuster",
        "target",
        [_sample_finding("Web path discovered: /admin")],
        tool_dir,
    )

    index = (tool_dir / "_index.md").read_text()

    assert "| Finding | Severity | MITRE |" in index
    assert "Scan Completed - No Findings" not in index


def test_tool_index_includes_raw_path(tmp_path: Path) -> None:
    tool_dir = tmp_path / "findings" / "gobuster"
    tool_dir.mkdir(parents=True)
    raw_path = tmp_path / "raw" / "gobuster.txt"

    write_tool_index("gobuster", "target", [], tool_dir, raw_path=raw_path)

    index = (tool_dir / "_index.md").read_text()
    assert str(raw_path) in index


def test_credential_path_ntlm_in_ntlm_folder(tmp_path: Path) -> None:
    credential = Credential("administrator", "HASH", "ntlm", "10.0.0.1", "LAB")

    path = _credential_path(credential, tmp_path)

    assert path == tmp_path / "credentials" / "ntlm" / "administrator.md"


def test_credential_path_plaintext_folder(tmp_path: Path) -> None:
    credential = Credential("brandon.stark", "pass", "plaintext", "10.0.0.1", "NORTH")

    path = _credential_path(credential, tmp_path)

    assert path == tmp_path / "credentials" / "plaintext" / "brandon-stark.md"


def test_domain_users_in_users_subfolder(tmp_path: Path) -> None:
    obj = DomainObject(name="john.doe", object_type="user", domain="north.local")

    path = _domain_path(obj, tmp_path)

    assert path == tmp_path / "domain" / "users" / "john-doe.md"


def test_finding_collision_adds_hash_suffix(tmp_path: Path) -> None:
    finding = _sample_finding("SMB Signing Disabled", finding_hash="abcdef123456")
    existing = tmp_path / "findings" / "cme" / "smb-signing-disabled.md"
    existing.parent.mkdir(parents=True)
    existing.write_text("---\nhash: different\n---\n", encoding="utf-8")

    path = _finding_path(finding, "cme", tmp_path)

    assert path.name == "smb-signing-disabled-abcdef.md"


def test_finding_note_filename_starts_with_readable_context(tmp_path: Path) -> None:
    finding = Finding(
        title="Web virtual host discovered: staging.silentium.htb",
        severity=Severity.LOW,
        mitre_matches=[],
        affected_hosts=["silentium.htb"],
        evidence="staging.silentium.htb Status: 200 [Size: 3142]",
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash="bd1bbab42d820f8fee869d29263bf8c66b0be19396f20859babf88d06eec8a46",
    )
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[finding],
        domain_objects=[],
        raw_text="",
    )

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert written[0] == tmp_path / "findings" / "gobuster" / "staging.md"


def test_finding_note_filename_keeps_short_hash_suffix(tmp_path: Path) -> None:
    finding = Finding(
        title="SMB Signing Disabled",
        severity=Severity.HIGH,
        mitre_matches=[],
        affected_hosts=["192.168.56.11"],
        evidence="signing:False",
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash="abc123def4567890",
    )
    result = ParsedResult(
        tool="crackmapexec",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[finding],
        domain_objects=[],
        raw_text="",
    )

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert written[0] == (
        tmp_path / "findings" / "crackmapexec" / "smb-signing-disabled.md"
    )


def test_finding_note_filename_removes_duplicate_host_suffix(tmp_path: Path) -> None:
    finding = Finding(
        title="Web virtual host discovered: git-head.silentium.htb",
        severity=Severity.INFO,
        mitre_matches=[],
        affected_hosts=["silentium.htb"],
        evidence=".git/HEAD.silentium.htb Status: 400 [Size: 166]",
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash="b064560f92ae8009422da877144a9374",
    )
    result = ParsedResult(
        tool="gobuster",
        partial=False,
        hosts=[],
        credentials=[],
        findings=[finding],
        domain_objects=[],
        raw_text="",
    )

    written = write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    assert written[0] == tmp_path / "findings" / "gobuster" / "git-head.md"


def test_index_timeline_and_report_generators(tmp_path: Path) -> None:
    result = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())
    write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    index_path = write_index(
        result.findings,
        tmp_path,
        engagement_name="Client_2026",
        scope=["192.168.56.0/24"],
    )
    timeline_path = write_timeline(
        result.findings,
        tmp_path,
        engagement_name="Client_2026",
    )
    report_paths = write_report(
        result.findings,
        tmp_path,
        engagement_name="Client_2026",
        report_format="both",
        with_defenses=True,
    )

    assert "T1557.001" in index_path.read_text()
    assert "Administrative access confirmed" in timeline_path.read_text()
    assert len(report_paths) == 2


def test_finding_note_confidence_chain_and_defenses_are_polished() -> None:
    result = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())
    markdown = render_credential_markdown(
        result.credentials[0],
        engagement_name="Client_2026",
        tool_name="crackmapexec",
        iso_timestamp="2026-04-27T20:10:23+00:00",
    )
    finding = result.findings[0]
    finding.mitre_matches = [
        MitreMatch("T1021.002", "SMB", "Lateral Movement", 0.4, "rule")
    ]
    finding.defenses = []
    rendered = render_finding_markdown(
        finding,
        engagement_name="Client_2026",
        tool_name="crackmapexec",
        hostname="DC01",
        iso_timestamp="2026-04-27T20:10:23+00:00",
    )

    assert "40%" in rendered
    assert "chain: null" not in rendered
    assert "| Technique | D3FEND ID | Description |" in rendered
    assert "hostname: DC01" in rendered
    assert "tags: [credential" in markdown


def test_report_has_summary_and_recommendations(tmp_path: Path) -> None:
    result = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())
    write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    report_paths = write_report(
        result.findings,
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
        with_defenses=True,
    )
    report = report_paths[0].read_text()

    assert "## Executive Summary" in report
    assert "## Top 5 Risks" in report
    assert "#### Recommendations" in report


def test_report_has_executive_summary_section(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("Critical Risk", Severity.CRITICAL)]
    )

    assert "## Executive Summary" in report
    assert "| Critical | 1 |" in report


def test_report_sorts_findings_by_severity(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path,
        [
            _report_finding("Low Risk", Severity.LOW),
            _report_finding("Critical Risk", Severity.CRITICAL),
        ],
    )

    assert report.index("### Critical Risk") < report.index("### Low Risk")


def test_report_includes_chain_section_when_chains_detected(tmp_path: Path) -> None:
    findings = [
        _report_finding("Discovery", Severity.MEDIUM, "T1046"),
        _report_finding("Kerberoast", Severity.HIGH, "T1558.003"),
        _report_finding("Pass the Hash", Severity.HIGH, "T1550.002"),
        _report_finding("SAM Dump", Severity.CRITICAL, "T1003.002"),
    ]

    report = _write_test_report(tmp_path, findings)

    assert "## Attack Chains Detected" in report
    assert "Full AD Compromise Path" in report


def test_report_includes_affected_assets_table(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("Critical Risk", Severity.CRITICAL)]
    )

    assert "## Affected Assets" in report
    assert "| 10.0.0.1 | 1 |" in report


def test_report_redacts_secrets_with_flag(tmp_path: Path) -> None:
    finding = _report_finding(
        "Credential Exposure",
        Severity.HIGH,
        evidence="alice:Secret123!",
    )
    paths = write_report(
        [finding],
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
        redact=True,
    )

    report = paths[0].read_text()

    assert "Secret123!" not in report
    assert "[REDACTED]" in report


def test_report_has_remediation_roadmap_section(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("SMB Signing Disabled", Severity.HIGH)]
    )

    assert "## Remediation Roadmap" in report
    assert "| 1 | SMB Signing Disabled | High | Low |" in report


def test_report_remediation_sorted_by_priority(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path,
        [
            _report_finding("Low Risk", Severity.LOW),
            _report_finding("Critical Risk", Severity.CRITICAL),
        ],
    )

    assert report.index("| 1 | Critical Risk") < report.index("| 2 | Low Risk")


def test_report_remediation_effort_low_for_signing(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("SMB Signing Disabled", Severity.HIGH)]
    )

    assert "| 1 | SMB Signing Disabled | High | Low |" in report


def test_report_shows_fixed_findings_section(tmp_path: Path) -> None:
    old = _report_finding("Anonymous FTP", Severity.MEDIUM)
    paths = write_report(
        [],
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
        previous_findings=[old],
    )

    report = paths[0].read_text()
    assert "## Fixed Since Last Engagement" in report
    assert "~~Anonymous FTP~~ (was medium)" in report


def test_report_recommendation_generated_for_smb_relay(tmp_path: Path) -> None:
    report = _write_test_report(
        tmp_path, [_report_finding("SMB Relay Possible", Severity.HIGH, "T1557.001")]
    )

    assert "Enable SMB signing and LDAP signing" in report
    assert "Disable LLMNR and NBT-NS" in report


def test_report_recommendation_generated_for_kerberoastable(
    tmp_path: Path,
) -> None:
    report = _write_test_report(
        tmp_path,
        [_report_finding("Kerberoastable Account", Severity.HIGH, "T1558.003")],
    )

    assert "Use strong passwords (25+ chars) for service accounts" in report
    assert "Group Managed Service Accounts" in report


def test_report_html_contains_donut_chart_svg(tmp_path: Path) -> None:
    finding = _report_finding("SMB Relay", Severity.HIGH, "T1557.001")

    path = write_report(
        [finding], tmp_path, engagement_name="Client", report_format="html"
    )[0]
    report = path.read_text(encoding="utf-8")

    assert '<svg class="donut"' in report
    assert "<path d=" in report


def test_report_html_contains_risk_bars(tmp_path: Path) -> None:
    finding = _report_finding("SMB Relay", Severity.HIGH, "T1557.001")

    path = write_report(
        [finding], tmp_path, engagement_name="Client", report_format="html"
    )[0]
    report = path.read_text(encoding="utf-8")

    assert "risk-bars" in report
    assert "risk-fill" in report


def test_report_html_has_dark_mode_toggle(tmp_path: Path) -> None:
    path = write_report([], tmp_path, engagement_name="Client", report_format="html")[0]
    report = path.read_text(encoding="utf-8")

    assert "toggleTheme()" in report
    assert "prefers-color-scheme: dark" in report


def test_report_html_finding_cards_collapsible(tmp_path: Path) -> None:
    finding = _report_finding("Critical Risk", Severity.CRITICAL)

    path = write_report(
        [finding], tmp_path, engagement_name="Client", report_format="html"
    )[0]
    report = path.read_text(encoding="utf-8")

    assert '<details class="finding-card severity-critical">' in report
    assert '<summary class="finding-summary">' in report


def test_report_html_cover_page_has_client_name(tmp_path: Path) -> None:
    path = write_report(
        [], tmp_path, engagement_name="Fallback Client", report_format="html"
    )[0]
    report = path.read_text(encoding="utf-8")

    assert "Fallback Client" in report
    assert "CONFIDENTIAL" in report


def test_report_html_print_stylesheet_present(tmp_path: Path) -> None:
    path = write_report([], tmp_path, engagement_name="Client", report_format="html")[0]
    report = path.read_text(encoding="utf-8")

    assert "@media print" in report
    assert "print-color-adjust" in report


def test_donut_chart_data_correct_segments() -> None:
    chart = build_donut_chart_data(1, 2, 0, 0, 1)

    assert chart["total"] == 4
    assert [segment["name"] for segment in chart["segments"]] == [
        "critical",
        "high",
        "info",
    ]


def test_donut_chart_handles_zero_findings() -> None:
    chart = build_donut_chart_data(0, 0, 0, 0, 0)

    assert chart["segments"] == []
    assert chart["total"] == 0
    assert chart["empty_color"] == "#94a3b8"


def test_arc_path_valid_svg_syntax() -> None:
    from xml.etree import ElementTree

    path = _arc_path(100, 100, 80, 50, -90, 90)
    ElementTree.fromstring(
        f'<svg xmlns="http://www.w3.org/2000/svg"><path d="{path}"/></svg>'
    )

    assert path.startswith("M ")
    assert path.endswith(" Z")


def test_tactic_bars_built_from_findings() -> None:
    findings = [
        _report_finding("SMB Relay", Severity.HIGH, "T1557.001"),
        _report_finding("Kerberoast", Severity.HIGH, "T1558.003"),
    ]

    bars = build_tactic_bars(findings)

    assert bars
    assert any(bar["count"] >= 1 for bar in bars)


def test_credential_note_has_mitre_tags_plaintext() -> None:
    markdown = _render_credential(secret_type="plaintext")

    assert "tags: [credential, plaintext, T1078, T1110.001]" in markdown


def test_credential_note_has_mitre_tags_ntlm() -> None:
    markdown = _render_credential(secret_type="ntlm")

    assert "tags: [credential, ntlm, T1078, T1550.002]" in markdown


def test_credential_note_severity_plaintext_is_critical() -> None:
    markdown = _render_credential(secret_type="plaintext")

    assert "severity: critical" in markdown


def test_credential_note_severity_ntlm_is_high() -> None:
    markdown = _render_credential(secret_type="ntlm")

    assert "severity: high" in markdown


def test_credential_note_cracked_false_shows_cross() -> None:
    markdown = _render_credential(cracked=False)

    assert "| Cracked | ✗ |" in markdown
    assert "| Cracked Value |" not in markdown


def test_credential_note_cracked_true_shows_tick() -> None:
    markdown = _render_credential(cracked=True, cracked_value="P@ssw0rd")

    assert "| Cracked | ✓ |" in markdown
    assert "| Cracked Value | P@ssw0rd |" in markdown


def test_credential_next_steps_plaintext_contains_evil_winrm() -> None:
    steps = get_credential_next_steps(
        "brandon.stark",
        "iseedeadpeople",
        "plaintext",
        "192.168.56.11",
        "north.sevenkingdoms.local",
    )

    assert any("evil-winrm" in step for step in steps)


def test_credential_next_steps_ntlm_contains_pth() -> None:
    steps = get_credential_next_steps(
        "Administrator",
        "aad3b435...",
        "ntlm",
        "192.168.56.11",
        "CORP",
    )

    assert any("Pass the Hash" in step for step in steps)


def test_credential_next_steps_subnet_derived_correctly() -> None:
    steps = get_credential_next_steps(
        "user",
        "pass",
        "plaintext",
        "192.168.56.11",
        "CORP",
    )

    assert any("192.168.56.0/24" in step for step in steps)


def test_credential_next_steps_invalid_ip_uses_host_as_is() -> None:
    steps = get_credential_next_steps(
        "user",
        "pass",
        "plaintext",
        "not-an-ip",
        "CORP",
    )

    assert any("not-an-ip/24" in step for step in steps)


def test_credential_note_related_finding_link() -> None:
    markdown = _render_credential(related_finding_hash="701365f769")

    assert "## Related Findings" in markdown
    assert "[[701365f769-valid-credential-identified]]" in markdown


def test_write_result_markdown_links_credential_to_source_finding(
    tmp_path: Path,
) -> None:
    result = CrackMapExecParser().parse((FIXTURES / "cme_sample.txt").read_text())

    write_result_markdown(result, tmp_path, engagement_name="Client_2026")

    note = (tmp_path / "credentials" / "plaintext" / "alice.md").read_text()
    assert "## Related Findings" in note
    assert "- [[" in note
    assert "-valid-credential-identified]]" in note


def test_credential_note_no_related_finding_section_when_none() -> None:
    markdown = _render_credential(related_finding_hash=None)

    assert "## Related Findings" not in markdown


def _write_test_report(tmp_path: Path, findings: list[Finding]) -> str:
    paths = write_report(
        findings,
        tmp_path,
        engagement_name="Client_2026",
        report_format="markdown",
        with_defenses=True,
    )
    return paths[0].read_text()


def _report_finding(
    title: str,
    severity: Severity,
    technique_id: str = "T1190",
    evidence: str = "example evidence",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        mitre_matches=[
            MitreMatch(
                technique_id,
                technique_id,
                "Credential Access",
                1.0,
                "rule",
            )
        ],
        affected_hosts=["10.0.0.1"],
        evidence=evidence,
        next_steps=["Remediate the issue."],
        defenses=[],
        chain_member=None,
        hash=title.casefold().replace(" ", "-"),
    )


def _render_credential(
    *,
    secret_type: str = "plaintext",
    cracked: bool = False,
    cracked_value: str | None = None,
    related_finding_hash: str | None = None,
) -> str:
    return render_credential_markdown(
        Credential(
            username="brandon.stark",
            secret="iseedeadpeople",
            secret_type=secret_type,
            source_host="192.168.56.11",
            domain="north.sevenkingdoms.local",
            cracked=cracked,
            cracked_value=cracked_value,
            related_finding_hash=related_finding_hash,
        ),
        engagement_name="penwinterfellloot",
        tool_name="crackmapexec",
        iso_timestamp="2026-04-27T20:10:23+00:00",
    )
