from __future__ import annotations

import asyncio
import json
import tomllib
from pathlib import Path

from click.testing import CliRunner
from pentnote.cli import main
from pentnote.core.engagement import init_engagement, load_findings, save_findings
from pentnote.evidence.linker import append_evidence_link
from pentnote.generators.markdown import render_finding_markdown, render_host_markdown
from pentnote.ghostlog.apply import (
    _validate_credential,
    _validate_finding,
    apply_extraction,
)
from pentnote.ghostlog.daemon import (
    is_interesting_command,
    normalize_history_line,
    process_history_lines,
    redact_command_secrets,
    start_daemon,
    stop_daemon,
)
from pentnote.ghostlog.llm import GhostLogExtraction, build_extraction_prompt
from pentnote.ghostlog.sanitize import sanitize_terminal_text
from pentnote.graph.bloodhound import (
    DomainGraph,
    GraphEdge,
    GraphNode,
    load_bloodhound_graph,
)
from pentnote.graph.canvas import attack_path_summary, build_canvas, write_canvas
from pentnote.graph.layout import LayoutMode, compute_layout, layout_nodes
from pentnote.models import (
    DefenseProfile,
    Finding,
    Host,
    MitreMatch,
    PayloadContext,
    Severity,
    WorkspaceCredential,
)
from pentnote.payloads.context import _detect_defenses, build_contexts
from pentnote.payloads.lotl import generate_lotl_steps
from pentnote.payloads.render import refresh_payloads
from pentnote.workspace.log import find_logs_for_finding
from pentnote.workspace.store import WorkspaceStore, credential_id

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_init_creates_local_config_and_gitignore() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "Operator", "--output", "vault"])

        assert result.exit_code == 0, result.output
        assert Path("vault/.pentnote/config.json").exists()
        assert Path("vault/.pentnote/local.json").exists()
        gitignore = Path("vault/.gitignore").read_text()
        assert ".pentnote/local.json" in gitignore


def test_log_daemon_outside_vault_shows_clean_error() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["log", "--daemon"])

    assert result.exit_code != 0
    assert "No PentNote engagement found" in result.output
    assert "Traceback" not in result.output


def test_pyproject_public_extras_are_simplified() -> None:
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
    extras = pyproject["project"]["optional-dependencies"]

    assert set(extras) == {"operator", "dev"}
    assert any(requirement.startswith("ollama") for requirement in extras["operator"])
    assert any(requirement.startswith("networkx") for requirement in extras["operator"])
    assert any(requirement.startswith("mypy") for requirement in extras["dev"])


def test_bloodhound_canvas_contains_file_nodes_and_edges(tmp_path: Path) -> None:
    graph = load_bloodhound_graph(
        FIXTURES / "bloodhound_sample.json", vault_root=tmp_path
    )
    canvas = build_canvas(graph)

    assert len(canvas["nodes"]) == 2
    assert len(canvas["edges"]) == 1
    assert {node["type"] for node in canvas["nodes"]} == {"file"}
    assert canvas["edges"][0]["label"] == "MemberOf"
    assert all("label" not in node for node in canvas["nodes"])
    assert any(
        node["file"] == "notes/domain/users/alice-lab-local.md"
        for node in canvas["nodes"]
    )
    assert any(
        node["file"] == "notes/domain/groups/domain-admins-lab-local.md"
        and node["color"] == "#FF4444"
        for node in canvas["nodes"]
    )


def test_canvas_maps_node_types_to_operator_note_paths() -> None:
    graph = DomainGraph(
        nodes=[
            GraphNode(
                id="WS01$",
                name="WS01$",
                object_type="Computer",
                note_path="legacy",
            ),
            GraphNode(
                id="LAB.LOCAL",
                name="LAB.LOCAL",
                object_type="Domain",
                note_path="legacy",
            ),
            GraphNode(
                id="LAB\\bob",
                name="LAB\\bob",
                object_type="User",
                note_path="legacy",
            ),
        ],
        edges=[
            GraphEdge(
                source="LAB\\bob",
                target="WS01$",
                relationship="GenericAll",
            )
        ],
    )

    canvas = build_canvas(graph)
    files = {node["file"] for node in canvas["nodes"]}

    assert "notes/hosts/ws01.md" in files
    assert "notes/credentials/plaintext/bob.md" in files
    assert "notes/domain/lab-local.md" in files
    assert canvas["edges"][0]["color"] == "1"


def test_canvas_prefers_existing_generated_domain_notes(tmp_path: Path) -> None:
    existing_note = tmp_path / "notes" / "domain" / "user-guest-north-local.md"
    existing_note.parent.mkdir(parents=True)
    existing_note.write_text("# Guest\n", encoding="utf-8")
    graph = DomainGraph(
        nodes=[
            GraphNode(
                id="GUEST@NORTH.LOCAL",
                name="GUEST@NORTH.LOCAL",
                object_type="User",
                note_path="notes/domain/user-guest-north-local.md",
            )
        ],
        edges=[],
    )

    canvas = build_canvas(graph, vault_root=tmp_path)

    assert canvas["nodes"][0]["file"] == "notes/domain/user-guest-north-local.md"


def test_canvas_prefers_existing_domain_scoped_credential_notes(tmp_path: Path) -> None:
    existing_note = tmp_path / "notes" / "credentials" / "north-local-guest.md"
    existing_note.parent.mkdir(parents=True)
    existing_note.write_text("# Guest credential\n", encoding="utf-8")
    graph = DomainGraph(
        nodes=[
            GraphNode(
                id="GUEST@NORTH.LOCAL",
                name="GUEST@NORTH.LOCAL",
                object_type="User",
                note_path="notes/domain/user-guest-north-local.md",
            )
        ],
        edges=[],
    )

    canvas = build_canvas(graph, vault_root=tmp_path)

    assert canvas["nodes"][0]["file"] == "notes/credentials/north-local-guest.md"


def test_canvas_warns_on_missing_notes(tmp_path: Path, capsys) -> None:
    graph = DomainGraph(
        nodes=[
            GraphNode(
                id="missing",
                name="Missing Note",
                object_type="unknown",
                note_path="notes/domain/missing.md",
            )
        ],
        edges=[],
    )

    result = write_canvas(graph, tmp_path / "paths.canvas", vault_root=tmp_path)
    captured = capsys.readouterr()

    assert result.missing_notes == graph.nodes
    assert "Canvas node(s) link to notes that do not exist yet" in captured.err
    assert "Missing Note -> notes/domain/missing.md" in captured.err


def test_canvas_writes_even_when_notes_missing(tmp_path: Path) -> None:
    graph = DomainGraph(
        nodes=[
            GraphNode(
                id="missing",
                name="Missing Note",
                object_type="unknown",
                note_path="notes/domain/missing.md",
            )
        ],
        edges=[],
    )

    result = write_canvas(graph, tmp_path / "paths.canvas", vault_root=tmp_path)

    assert result.written.exists()
    assert json.loads(result.written.read_text(encoding="utf-8"))["nodes"]


def test_canvas_no_warning_when_all_notes_exist(tmp_path: Path, capsys) -> None:
    note_path = tmp_path / "notes" / "domain" / "present.md"
    note_path.parent.mkdir(parents=True)
    note_path.write_text("# Present\n", encoding="utf-8")
    graph = DomainGraph(
        nodes=[
            GraphNode(
                id="present",
                name="Present",
                object_type="unknown",
                note_path="notes/domain/present.md",
            )
        ],
        edges=[],
    )

    result = write_canvas(graph, tmp_path / "paths.canvas", vault_root=tmp_path)
    captured = capsys.readouterr()

    assert result.missing_notes == []
    assert captured.err == ""


def test_layout_nodes_is_deterministic_and_non_overlapping() -> None:
    node_ids = [f"node-{index}" for index in range(12)]
    edges = [
        (f"node-{index}", f"node-{(index + 1) % len(node_ids)}")
        for index in range(len(node_ids))
    ]

    first = layout_nodes(node_ids, edges)
    second = layout_nodes(list(reversed(node_ids)), reversed(edges))

    assert first == second
    positions = list(first.items())
    for index, (source_id, (source_x, source_y)) in enumerate(positions):
        for target_id, (target_x, target_y) in positions[index + 1 :]:
            overlaps_x = abs(source_x - target_x) < 360
            overlaps_y = abs(source_y - target_y) < 190
            assert not overlaps_x or not overlaps_y, (source_id, target_id)


def test_layout_auto_selects_radial_for_small_graph() -> None:
    graph = _graph_with_nodes(5)

    assert compute_layout(graph, LayoutMode.AUTO) == compute_layout(
        graph, LayoutMode.RADIAL
    )


def test_layout_auto_selects_grid_for_large_graph() -> None:
    graph = _graph_with_nodes(101)

    assert compute_layout(graph, LayoutMode.AUTO) == compute_layout(
        graph, LayoutMode.GRID
    )


def test_radial_layout_places_domain_at_center() -> None:
    graph = DomainGraph(
        nodes=[
            GraphNode(
                id="domain",
                name="LAB.LOCAL",
                object_type="domain",
                note_path="notes/domain/lab-local.md",
            ),
            GraphNode(
                id="user",
                name="alice",
                object_type="user",
                note_path="notes/credentials/alice.md",
            ),
        ],
        edges=[],
    )

    positions = compute_layout(graph, LayoutMode.RADIAL)

    assert positions["domain"] == (0, 0)


def test_canvas_nodes_have_role_colors() -> None:
    graph = DomainGraph(
        nodes=[
            GraphNode(
                id="dc",
                name="DC01$",
                object_type="computer",
                note_path="notes/hosts/dc01.md",
                properties={"isDC": True},
            ),
            GraphNode(
                id="svc",
                name="svc_sql",
                object_type="user",
                note_path="notes/credentials/svc-sql.md",
                properties={"hasSPN": True},
            ),
        ],
        edges=[],
    )

    colors = {node["file"]: node["color"] for node in build_canvas(graph)["nodes"]}

    assert colors["notes/hosts/dc01.md"] == "#FF8800"
    assert colors["notes/credentials/svc-sql.md"] == "#FFAA00"


def test_bloodhound_attack_path_edges_detected(tmp_path: Path) -> None:
    input_path = tmp_path / "bloodhound.json"
    input_path.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "ALICE", "name": "ALICE@LAB.LOCAL", "type": "user"},
                    {"id": "DA", "name": "Domain Admins@LAB.LOCAL", "type": "group"},
                    {"id": "DC01", "name": "DC01$", "type": "computer"},
                ],
                "edges": [
                    {"source": "ALICE", "target": "DA", "relationship": "MemberOf"},
                    {"source": "ALICE", "target": "DC01", "relationship": "AdminTo"},
                ],
                "ShortestPaths": [
                    {"source": "ALICE", "target": "DA"},
                ],
            }
        ),
        encoding="utf-8",
    )

    graph = load_bloodhound_graph(input_path, vault_root=tmp_path)
    path_types = {(edge.relationship, edge.path_type) for edge in graph.edges}

    assert ("MemberOf", "shortest_path") in path_types
    assert ("AdminTo", "attack_path") in path_types


def test_canvas_shortest_path_edge_has_red_color() -> None:
    graph = _path_graph("shortest_path")

    edge = build_canvas(graph, highlight_paths=True)["edges"][0]

    assert edge["color"] == "#FF4444"
    assert edge["width"] == 3


def test_canvas_attack_path_edge_has_orange_color() -> None:
    graph = _path_graph("attack_path")

    edge = build_canvas(graph, highlight_paths=True)["edges"][0]

    assert edge["color"] == "#FF8800"
    assert edge["width"] == 2


def test_canvas_normal_edge_has_gray_color() -> None:
    graph = _path_graph("normal")

    edge = build_canvas(graph, highlight_paths=True)["edges"][0]

    assert edge["color"] == "#888888"
    assert edge["width"] == 1


def test_canvas_highlight_paths_adds_legend_node() -> None:
    graph = _path_graph("shortest_path")

    nodes = build_canvas(graph, highlight_paths=True)["nodes"]

    assert nodes[0]["type"] == "text"
    assert "Attack Path Legend" in nodes[0]["text"]
    assert "Shortest Path to DA" in nodes[0]["text"]


def test_canvas_path_summary_shows_count() -> None:
    summary = attack_path_summary(_path_graph("shortest_path"))

    assert summary["shortest_paths"] == 1
    assert summary["attack_paths"] == 1
    assert summary["critical_edges"] == ["AdminTo"]


def test_canvas_warns_on_large_graph(tmp_path: Path, capsys) -> None:
    graph = _graph_with_nodes(101)

    write_canvas(graph, tmp_path / "large.canvas", vault_root=tmp_path)
    captured = capsys.readouterr()

    assert "Large graph (101 nodes)" in captured.err


def test_canvas_layout_flag_respected(tmp_path: Path, monkeypatch) -> None:
    init_engagement(tmp_path, "Operator", [])
    input_path = tmp_path / "bloodhound.json"
    input_path.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "LAB", "name": "LAB.LOCAL", "type": "domain"},
                    {"id": "ALICE", "name": "ALICE@LAB.LOCAL", "type": "user"},
                ],
                "edges": [
                    {"source": "ALICE", "target": "LAB", "relationship": "MemberOf"}
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "sync",
            "--graph",
            "--bloodhound-json",
            str(input_path),
            "--canvas-output",
            "radial.canvas",
            "--layout",
            "radial",
        ],
    )

    assert result.exit_code == 0, result.output
    canvas = json.loads((tmp_path / "radial.canvas").read_text(encoding="utf-8"))
    domain_node = next(node for node in canvas["nodes"] if "lab-local" in node["file"])
    assert (domain_node["x"], domain_node["y"]) == (0, 0)


def test_cli_graph_canvas_writes_canvas(tmp_path: Path, monkeypatch) -> None:
    init_engagement(tmp_path, "Operator", [])
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        main,
        [
            "sync",
            "--graph",
            "--bloodhound-json",
            str(FIXTURES / "bloodhound_sample.json"),
            "--canvas-output",
            "paths.canvas",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / "paths.canvas").read_text())
    assert data["nodes"]
    assert data["edges"]


def test_graph_canvas_accepts_sharphound_collection_folder(tmp_path: Path) -> None:
    collection = tmp_path / "loot-blood"
    collection.mkdir()
    (collection / "users.json").write_text(
        json.dumps(
            {
                "meta": {"type": "users", "count": 1},
                "data": [
                    {
                        "ObjectIdentifier": "S-1-5-21-1000",
                        "Properties": {"name": "ALICE@LAB.LOCAL"},
                    }
                ],
            }
        )
    )
    (collection / "groups.json").write_text(
        json.dumps(
            {
                "meta": {"type": "groups", "count": 1},
                "data": [
                    {
                        "ObjectIdentifier": "S-1-5-21-512",
                        "Properties": {"name": "DOMAIN ADMINS@LAB.LOCAL"},
                        "Members": [
                            {"ObjectIdentifier": "S-1-5-21-1000", "ObjectType": "User"}
                        ],
                    }
                ],
            }
        )
    )

    graph = load_bloodhound_graph(collection, vault_root=tmp_path)
    canvas = build_canvas(graph)

    assert len(canvas["nodes"]) == 2
    assert canvas["edges"][0]["label"] == "MemberOf"


def test_graph_canvas_discovers_sharphound_json_recursively(tmp_path: Path) -> None:
    collection = tmp_path / "loot-blood"
    collection.mkdir()
    (collection / "groups.json").write_text(
        json.dumps(
            {
                "meta": {"type": "groups", "count": 1},
                "data": [
                    {
                        "ObjectIdentifier": "S-1-5-21-512",
                        "Properties": {"name": "DOMAIN ADMINS@NORTH.LOCAL"},
                        "Members": [
                            {
                                "ObjectIdentifier": "S-1-5-21-501",
                                "ObjectType": "User",
                                "ObjectName": "GUEST@NORTH.LOCAL",
                            }
                        ],
                    }
                ],
            }
        )
    )

    graph = load_bloodhound_graph(tmp_path, vault_root=tmp_path)
    canvas = build_canvas(graph, vault_root=tmp_path)

    assert len(canvas["nodes"]) == 2
    assert any(
        node["file"] == "notes/domain/users/guest-north-local.md"
        for node in canvas["nodes"]
    )
    assert canvas["edges"][0]["label"] == "MemberOf"


def test_append_evidence_link_includes_ocr_comment(tmp_path: Path) -> None:
    notes_dir = tmp_path / "notes"

    path = append_evidence_link(
        notes_dir, "10.10.10.10", "screenshot.png", ocr_text="flag -- value"
    )

    text = path.read_text()
    assert "![[screenshot.png]]" in text
    assert "<!-- OCR: flag - value -->" in text


def test_payload_refresh_injects_context(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    _write_host_note(
        tmp_path,
        "10.10.10.10",
        os_name="Windows",
        ports=[445],
        hostname="WINTERFELL",
    )
    local = tmp_path / ".pentnote" / "local.json"
    local.write_text(json.dumps({"lhost": "10.10.14.2", "lport": 9001}) + "\n")
    store = WorkspaceStore(tmp_path)
    store.add_credential(
        {
            "id": credential_id("alice", "LAB", "plaintext"),
            "username": "alice",
            "domain": "LAB",
            "secret": "Password123!",
            "secret_type": "plaintext",
            "source_host": "10.10.10.10",
            "source_tool": "test",
            "cracked": False,
            "cracked_value": None,
            "tags": [],
            "notes": "",
        }
    )

    paths = refresh_payloads(engagement, host="10.10.10.10")

    assert paths
    text = paths[0].read_text()
    assert "## Payload Guidance — WINTERFELL" in text
    assert "cme smb 10.10.10.10 -u alice -p Password123! --shares" in text
    assert "{context" not in text


def test_payload_context_uses_open_ports(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    _write_host_note(tmp_path, "10.10.10.20", os_name="Linux", ports=[22, 80])

    contexts = build_contexts(engagement, host="10.10.10.20")

    assert contexts[0].open_ports == [22, 80]


def test_payload_context_uses_credentials(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    _write_host_note(tmp_path, "10.10.10.30", os_name="Windows", ports=[445])
    WorkspaceStore(tmp_path).add_credential(
        {
            "id": credential_id("alice", "LAB", "plaintext"),
            "username": "alice",
            "domain": "LAB",
            "secret": "Password123!",
            "secret_type": "plaintext",
            "source_host": "10.10.10.30",
            "source_tool": "test",
        }
    )

    contexts = build_contexts(engagement, host="10.10.10.30")

    assert contexts[0].credentials[0].username == "alice"
    assert contexts[0].domain == "LAB"


def test_payload_lotl_windows_smb_with_ntlm() -> None:
    context = _payload_context(
        os_name="Windows",
        ports=[445],
        credentials=[
            WorkspaceCredential(
                username="Administrator",
                domain="LAB",
                secret="31d6cfe0d16ae931b73c59d7e0c089c0",
                secret_type="ntlm",
                source_host="10.10.10.40",
            )
        ],
    )

    commands = generate_lotl_steps(context)

    assert (
        "cme smb 10.10.10.40 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 --shares"
        in commands
    )
    assert all(" -p " not in command for command in commands)


def test_payload_lotl_windows_smb_with_plaintext() -> None:
    context = _payload_context(
        os_name="Windows",
        ports=[445],
        credentials=[
            WorkspaceCredential(
                username="alice",
                domain="LAB",
                secret="Password123!",
                secret_type="plaintext",
                source_host="10.10.10.40",
            )
        ],
    )

    commands = generate_lotl_steps(context)

    assert "cme smb 10.10.10.40 -u alice -p Password123! --shares" in commands
    assert all(" -H " not in command for command in commands)


def test_payload_lotl_linux_ssh() -> None:
    context = _payload_context(
        os_name="Linux",
        ports=[22],
        credentials=[
            WorkspaceCredential(
                username="alice",
                secret="Password123!",
                secret_type="plaintext",
                source_host="10.10.10.40",
            )
        ],
    )

    assert "ssh alice@10.10.10.40" in generate_lotl_steps(context)


def test_payload_lotl_no_credentials_shows_generic() -> None:
    context = _payload_context(os_name="Linux", ports=[80], credentials=[])

    commands = generate_lotl_steps(context)

    assert (
        "gobuster dir -u http://10.10.10.40 -w /usr/share/wordlists/dirb/common.txt"
        in commands
    )


def test_payload_render_writes_to_host_note(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    _write_host_note(tmp_path, "10.10.10.50", os_name="Linux", ports=[80])

    paths = refresh_payloads(engagement, host="10.10.10.50")

    assert paths == [tmp_path / "notes" / "hosts" / "10-10-10-50.md"]
    assert "## Payload Guidance — 10.10.10.50" in paths[0].read_text()


def test_defense_profile_detects_defender_from_findings() -> None:
    profile = _detect_defenses(
        [_defense_finding("Windows Defender service MsMpEng observed")]
    )

    assert profile.av_detected == ["Windows Defender"]
    assert profile.amsi_present is True


def test_defense_profile_detects_crowdstrike() -> None:
    profile = _detect_defenses([_defense_finding("CrowdStrike CSFalcon installed")])

    assert profile.edr_detected == ["CrowdStrike"]
    assert profile.amsi_present is True


def test_defense_profile_no_av_returns_empty_lists() -> None:
    profile = _detect_defenses([_defense_finding("No endpoint tooling observed")])

    assert profile.av_detected == []
    assert profile.edr_detected == []
    assert profile.amsi_present is False


def test_defense_profile_uses_host_av_products() -> None:
    profile = _detect_defenses(
        [],
        [Host(ip="10.10.10.10", av_products=["CrowdStrike Falcon"])],
    )

    assert profile.edr_detected == ["CrowdStrike Falcon"]
    assert profile.amsi_present is True


def test_defense_profile_merges_host_and_finding_sources() -> None:
    profile = _detect_defenses(
        [_defense_finding("CrowdStrike CSFalcon installed")],
        [Host(ip="10.10.10.10", av_products=["Windows Defender"])],
    )

    assert profile.av_detected == ["Windows Defender"]
    assert profile.edr_detected == ["CrowdStrike"]


def test_host_note_includes_security_products_section() -> None:
    markdown = render_host_markdown(
        Host(
            ip="10.10.10.10",
            hostname="DC01",
            av_products=["Windows Defender", "CrowdStrike Falcon"],
        ),
        engagement_name="Operator",
        tool_name="crackmapexec",
        iso_timestamp="2026-05-03T00:00:00+00:00",
    )

    assert "## Security Products" in markdown
    assert "| Windows Defender | Detected |" in markdown
    assert "| CrowdStrike Falcon | Detected |" in markdown


def test_lotl_edr_present_returns_lotl_commands() -> None:
    context = _payload_context(
        os_name="Windows",
        ports=[445],
        credentials=[
            WorkspaceCredential(
                username="alice",
                domain="LAB",
                secret="Password123!",
                secret_type="plaintext",
                source_host="10.10.10.40",
            )
        ],
    )
    defenses = DefenseProfile(edr_detected=["CrowdStrike"])

    commands = generate_lotl_steps(context, defenses)

    assert (
        "cme smb 10.10.10.40 -u alice -p Password123! --exec-method mmcexec" in commands
    )
    assert "# EDR detected: CrowdStrike" in commands
    assert any(command.startswith("# Safe fallback:") for command in commands)


def test_lotl_no_edr_returns_standard_commands() -> None:
    context = _payload_context(
        os_name="Windows",
        ports=[445],
        credentials=[
            WorkspaceCredential(
                username="alice",
                domain="LAB",
                secret="Password123!",
                secret_type="plaintext",
                source_host="10.10.10.40",
            )
        ],
    )

    commands = generate_lotl_steps(context, DefenseProfile())

    assert "cme smb 10.10.10.40 -u alice -p Password123! --shares" in commands
    assert not any("mmcexec" in command for command in commands)


def test_payload_note_includes_defense_context_section(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    _write_host_note(tmp_path, "10.10.10.60", os_name="Windows", ports=[445])
    save_findings(engagement, [_defense_finding("CrowdStrike agent found")])

    paths = refresh_payloads(engagement, host="10.10.10.60")

    assert "## Defense Context" in paths[0].read_text(encoding="utf-8")


def test_payload_note_warning_callout_when_edr_detected(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    _write_host_note(tmp_path, "10.10.10.70", os_name="Windows", ports=[445])
    save_findings(engagement, [_defense_finding("CrowdStrike CSFalcon found")])

    paths = refresh_payloads(engagement, host="10.10.10.70")

    text = paths[0].read_text(encoding="utf-8")
    assert "> [!warning] EDR Detected" in text
    assert "CrowdStrike - use LOTL techniques" in text


def _write_host_note(
    vault_root: Path,
    host_ip: str,
    *,
    os_name: str,
    ports: list[int],
    hostname: str | None = None,
) -> Path:
    path = vault_root / "notes" / "hosts" / f"{host_ip.replace('.', '-')}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(
        f"| {port} | tcp | service-{port} | N/A | open |" for port in ports
    )
    path.write_text(
        "\n".join(
            [
                f"# {hostname or host_ip}",
                "",
                "## Target Info",
                "| Field | Value |",
                "| --- | --- |",
                f"| IP | {host_ip} |",
                f"| Hostname | {hostname or 'N/A'} |",
                f"| OS | {os_name} |",
                "| Tags | N/A |",
                "",
                "## Open Ports",
                "| Port | Protocol | Service | Version | State |",
                "| --- | --- | --- | --- | --- |",
                rows,
                "",
                "## Notes",
                "<!-- analyst notes here -->",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _payload_context(
    *,
    os_name: str,
    ports: list[int],
    credentials: list[WorkspaceCredential],
) -> PayloadContext:
    return PayloadContext(
        host_ip="10.10.10.40",
        hostname=None,
        os=os_name,
        open_ports=ports,
        credentials=credentials,
        domain=credentials[0].domain if credentials else None,
        lhost="10.10.14.2",
        lport=9001,
    )


def _defense_finding(evidence: str) -> Finding:
    return Finding(
        title="Endpoint tooling observed",
        severity=Severity.INFO,
        mitre_matches=[
            MitreMatch(
                "T1562.001",
                "Disable or Modify Tools",
                "Defense Evasion",
                0.5,
                "test",
            )
        ],
        affected_hosts=["10.10.10.60"],
        evidence=evidence,
        next_steps=[],
        defenses=[],
        chain_member=None,
        hash=evidence.casefold().replace(" ", "-")[:16],
    )


def _graph_with_nodes(count: int) -> DomainGraph:
    nodes = [
        GraphNode(
            id=f"node-{index}",
            name=f"node-{index}",
            object_type="computer",
            note_path=f"notes/hosts/node-{index}.md",
        )
        for index in range(count)
    ]
    return DomainGraph(nodes=nodes, edges=[])


def _path_graph(path_type: str) -> DomainGraph:
    return DomainGraph(
        nodes=[
            GraphNode(
                id="alice",
                name="alice",
                object_type="user",
                note_path="notes/credentials/alice.md",
            ),
            GraphNode(
                id="dc",
                name="DC01$",
                object_type="computer",
                note_path="notes/hosts/dc01.md",
            ),
        ],
        edges=[
            GraphEdge(
                source="alice",
                target="dc",
                relationship="AdminTo",
                path_type=path_type,
            )
        ],
    )


def test_ghostlog_sanitizer_removes_ansi_and_prompts() -> None:
    raw = "\x1b[31mkali@box:~/lab$ nmap 10.0.0.1\x1b[0m\r\nPORT 445/tcp open smb\n"

    clean = sanitize_terminal_text(raw)

    assert "\x1b" not in clean
    assert "kali@box" not in clean
    assert "PORT 445/tcp open smb" in clean


def test_ghostlog_prompt_uses_strict_json_contract() -> None:
    prompt = build_extraction_prompt("[+] 192.168.56.11:445 LAB\\alice:Password123!")

    assert "OUTPUT ONLY JSON" in prompt
    assert '"credentials"' in prompt
    assert '"target": "string (IP or domain, if known, else null)"' in prompt
    assert "[INSERT_SANITIZED_CHUNK_HERE]" not in prompt


def test_ghostlog_schema_accepts_requested_target_shape() -> None:
    extraction = GhostLogExtraction.model_validate(
        {
            "credentials": [
                {
                    "username": "alice",
                    "secret": "Password123!",
                    "secret_type": "plaintext",
                    "target": "192.168.56.11",
                }
            ],
            "findings": [
                {
                    "title": "Valid SMB credential",
                    "severity": "high",
                    "target": "192.168.56.11",
                    "evidence": "[+] 192.168.56.11:445 LAB\\alice:Password123!",
                }
            ],
            "notes": ["Valid SMB credential found on 192.168.56.11."],
        }
    )

    assert extraction.credentials[0].target == "192.168.56.11"


def test_ghostlog_filters_noise_and_redacts_history() -> None:
    assert is_interesting_command("ls -la") is False
    assert is_interesting_command("nxc smb 10.10.10.10 -u alice -p Secret123") is True

    command = normalize_history_line(
        ": 1710000000:0;nxc smb 10.10.10.10 -u alice -p Secret123"
    )

    assert command is not None
    assert command.interesting is True
    assert "Secret123" not in command.sanitized
    assert "<redacted>" in command.sanitized


def test_ghostlog_detects_certipy() -> None:
    assert is_interesting_command("certipy find -u alice -p Secret123") is True


def test_ghostlog_detects_evil_winrm() -> None:
    assert is_interesting_command("evil-winrm -i 10.10.10.10 -u alice") is True


def test_ghostlog_detects_netexec() -> None:
    assert is_interesting_command("netexec smb 10.10.10.10 -u alice") is True


def test_ghostlog_detects_pentnote_run_wrapped_tool() -> None:
    command = (
        "pentnote run gobuster vhost -u http://10.129.60.222 "
        "-w /usr/share/wordlists/dnsmap.txt --append-domain --exclude-status 400"
    )

    assert is_interesting_command(command) is True


def test_ghostlog_does_not_treat_other_pentnote_commands_as_tool_output() -> None:
    assert is_interesting_command("pentnote log --status") is False


def test_ghostlog_ignores_ls_and_cd() -> None:
    assert is_interesting_command("ls -la") is False
    assert is_interesting_command("cd /tmp") is False


def test_ghostlog_ignores_git_commands() -> None:
    assert is_interesting_command("git status --short") is False


def test_ghostlog_redacts_secret_shapes_before_llm() -> None:
    ntlm_pair = "aad3b435b51404eeaad3b435b51404ee:" "31d6cfe0d16ae931b73c59d7e0c089c0"
    long_hex = "0123456789abcdef" * 4
    command = (
        "nxc smb 10.10.10.10 -u alice --password Secret123 "
        f"--hashes {ntlm_pair} --api-key api-key-value "
        "curl -H 'Authorization: Bearer abcdefghijklmnop' "
        f"token=inline-token {long_hex}"
    )

    redacted = redact_command_secrets(command)

    assert "Secret123" not in redacted
    assert ntlm_pair not in redacted
    assert "api-key-value" not in redacted
    assert "abcdefghijklmnop" not in redacted
    assert "inline-token" not in redacted
    assert long_hex not in redacted
    assert redacted.count("<redacted>") >= 5


def test_ghostlog_process_history_updates_timeline_and_host(
    tmp_path: Path, monkeypatch
) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])

    def fake_extract_findings(
        text: str, *, model: str = "llama3"
    ) -> GhostLogExtraction:
        return GhostLogExtraction.model_validate(
            {
                "credentials": [],
                "findings": [
                    {
                        "title": "SMB admin access observed",
                        "severity": "high",
                        "target": "10.10.10.10",
                        "evidence": text,
                    }
                ],
                "notes": ["Interesting SMB command observed"],
            }
        )

    monkeypatch.setattr(
        "pentnote.ghostlog.daemon.extract_findings",
        fake_extract_findings,
    )

    result = asyncio.run(
        process_history_lines(
            engagement,
            [": 1710000000:0;nxc smb 10.10.10.10 -u alice -p Secret123"],
        )
    )

    assert result.processed == 1
    assert result.extracted_findings == 1
    assert (
        "SMB admin access observed" in (tmp_path / "notes" / "TIMELINE.md").read_text()
    )
    assert (
        "SMB admin access observed"
        in (tmp_path / "notes" / "hosts" / "10-10-10-10.md").read_text()
    )


def test_ghostlog_timeline_source_is_ghostlog(tmp_path: Path, monkeypatch) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])

    def fake_extract_findings(
        text: str, *, model: str = "llama3"
    ) -> GhostLogExtraction:
        return GhostLogExtraction.model_validate({})

    monkeypatch.setattr(
        "pentnote.ghostlog.daemon.extract_findings",
        fake_extract_findings,
    )

    asyncio.run(
        process_history_lines(
            engagement,
            [": 1710000000:0;pentnote run gobuster vhost -u http://10.10.10.10"],
        )
    )

    timeline = (tmp_path / "notes" / "TIMELINE.md").read_text()

    assert "| ghostlog | Ghost Log observed:" in timeline
    assert "| manual | Ghost Log observed:" not in timeline


def test_ghostlog_prints_summary_when_credentials_found(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])

    def fake_extract_findings(
        text: str, *, model: str = "llama3"
    ) -> GhostLogExtraction:
        return GhostLogExtraction.model_validate(
            {
                "credentials": [
                    {
                        "username": "alice",
                        "secret": "Password123!",
                        "secret_type": "plaintext",
                        "target": "10.10.10.10",
                    }
                ],
                "findings": [],
                "log_entries": ["Credential observed"],
            }
        )

    monkeypatch.setattr(
        "pentnote.ghostlog.daemon.extract_findings",
        fake_extract_findings,
    )

    asyncio.run(
        process_history_lines(
            engagement,
            [": 1710000000:0;nxc smb 10.10.10.10 -u alice -p Secret123"],
        )
    )

    captured = capsys.readouterr()
    assert "[ghost]" in captured.out
    assert "1 credential(s)" in captured.out
    assert "1 log entr(ies)" in captured.out


def test_ghostlog_silent_when_nothing_extracted(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])

    def fake_extract_findings(
        text: str, *, model: str = "llama3"
    ) -> GhostLogExtraction:
        return GhostLogExtraction()

    monkeypatch.setattr(
        "pentnote.ghostlog.daemon.extract_findings",
        fake_extract_findings,
    )

    asyncio.run(
        process_history_lines(
            engagement,
            [": 1710000000:0;nxc smb 10.10.10.10 -u alice -p Secret123"],
        )
    )

    captured = capsys.readouterr()
    assert "[ghost]" not in captured.out


def test_ghostlog_session_tracks_command_counts(tmp_path: Path, monkeypatch) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])

    def fake_extract_findings(
        text: str, *, model: str = "llama3"
    ) -> GhostLogExtraction:
        return GhostLogExtraction.model_validate(
            {
                "credentials": [
                    {
                        "username": "alice",
                        "secret": "Password123!",
                        "secret_type": "plaintext",
                        "target": "10.10.10.10",
                    }
                ],
                "findings": [
                    {
                        "title": "Valid SMB credential",
                        "severity": "high",
                        "target": "10.10.10.10",
                        "evidence": text,
                    }
                ],
            }
        )

    monkeypatch.setattr(
        "pentnote.ghostlog.daemon.extract_findings",
        fake_extract_findings,
    )

    asyncio.run(
        process_history_lines(
            engagement,
            ["ls -la", "nxc smb 10.10.10.10 -u alice -p Secret123"],
            quiet=True,
        )
    )

    session = json.loads((tmp_path / ".pentnote" / "ghostlog_session.json").read_text())
    assert session["commands_seen"] == 2
    assert session["commands_kept"] == 1
    assert session["credentials_found"] == 1
    assert session["findings_found"] == 1


def test_ghostlog_stop_prints_session_summary(tmp_path: Path, monkeypatch) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    start_daemon(engagement)

    def fake_extract_findings(
        text: str, *, model: str = "llama3"
    ) -> GhostLogExtraction:
        return GhostLogExtraction.model_validate(
            {"log_entries": ["Interesting command observed"]}
        )

    monkeypatch.setattr(
        "pentnote.ghostlog.daemon.extract_findings",
        fake_extract_findings,
    )
    asyncio.run(
        process_history_lines(
            engagement,
            ["nmap -sV 10.10.10.10"],
            quiet=True,
        )
    )
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["log", "--stop"], catch_exceptions=False)

    assert result.exit_code == 0, result.output
    assert "Ghost Log Session Summary" in result.output
    assert "Commands seen:" in result.output
    assert "Log entries:" in result.output


def test_ghostlog_status_shows_running_state(tmp_path: Path, monkeypatch) -> None:
    init_engagement(tmp_path, "Operator", [])
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    runner.invoke(main, ["log", "--start"])

    result = runner.invoke(main, ["log", "--status"])

    assert result.exit_code == 0, result.output
    assert "Ghost Log: RUNNING" in result.output
    assert "Commands processed:" in result.output


def test_ghostlog_status_shows_stopped_state(tmp_path: Path, monkeypatch) -> None:
    init_engagement(tmp_path, "Operator", [])
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    runner.invoke(main, ["log", "--start"])
    runner.invoke(main, ["log", "--stop"])

    result = runner.invoke(main, ["log", "--status"])

    assert result.exit_code == 0, result.output
    assert "Ghost Log: STOPPED" in result.output
    assert "Last session:" in result.output


def test_ghostlog_finding_has_source_command(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    extraction = GhostLogExtraction.model_validate(
        {
            "findings": [
                {
                    "title": "SMB admin access observed",
                    "severity": "high",
                    "target": "10.10.10.10",
                    "evidence": "admin login succeeded",
                }
            ]
        }
    )

    apply_extraction(
        engagement,
        extraction,
        source_command="crackmapexec smb 10.10.10.10 -u admin -p pass",
    )

    assert (
        load_findings(engagement)[0].source_command
        == "crackmapexec smb 10.10.10.10 -u admin -p pass"
    )


def test_ghostlog_log_entry_links_to_finding_hash(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    extraction = GhostLogExtraction.model_validate(
        {
            "findings": [
                {
                    "title": "SMB admin access observed",
                    "severity": "high",
                    "target": "10.10.10.10",
                    "evidence": "admin login succeeded",
                }
            ],
            "log_entries": ["Follow up on SMB admin access"],
        }
    )

    apply_extraction(engagement, extraction, source_command="nxc smb 10.10.10.10")

    finding_hash = load_findings(engagement)[0].hash
    logs = WorkspaceStore(tmp_path).load()["log"]
    assert any(entry.get("linked_finding_hash") == finding_hash for entry in logs)


def test_finding_note_includes_source_command_section() -> None:
    finding = _defense_finding("admin login succeeded")
    finding.source_command = "crackmapexec smb 10.10.10.10 -u admin -p pass"

    markdown = render_finding_markdown(
        finding,
        engagement_name="Operator",
        tool_name="ghostlog",
    )

    assert "## Source" in markdown
    assert "crackmapexec smb 10.10.10.10 -u admin -p pass" in markdown
    assert "Captured by Ghost Log" in markdown


def test_ghostlog_log_finding_query_returns_matching_entries(tmp_path: Path) -> None:
    init_engagement(tmp_path, "Operator", [])
    store = WorkspaceStore(tmp_path)
    store.add_log(
        {
            "message": "Ghost Log observed: nxc smb 10.10.10.10",
            "date": "2026-05-03T12:00:00+00:00",
            "host": "10.10.10.10",
            "tags": ["ghostlog"],
            "linked_finding_hash": "abc123",
        }
    )

    entries = find_logs_for_finding("abc123", store)

    assert len(entries) == 1
    assert entries[0].message.startswith("Ghost Log observed")


def test_ghostlog_log_finding_query_empty_when_no_match(tmp_path: Path) -> None:
    init_engagement(tmp_path, "Operator", [])
    store = WorkspaceStore(tmp_path)
    store.add_log(
        {
            "message": "Ghost Log observed: nmap 10.10.10.10",
            "date": "2026-05-03T12:00:00+00:00",
            "host": "10.10.10.10",
            "tags": ["ghostlog"],
            "linked_finding_hash": "abc123",
        }
    )

    assert find_logs_for_finding("missing", store) == []


def test_ghostlog_session_cumulative_increments_on_stop(
    tmp_path: Path, monkeypatch
) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    start_daemon(engagement)

    _patch_ghost_extract(
        monkeypatch,
        credentials=1,
        findings=1,
    )
    asyncio.run(
        process_history_lines(
            engagement,
            ["nxc smb 10.10.10.10 -u alice -p Secret123"],
            quiet=True,
        )
    )
    stop_daemon(engagement)

    session = _ghost_session(tmp_path)
    assert session["total_sessions"] == 1
    assert session["cumulative_commands_seen"] == 1
    assert session["cumulative_commands_kept"] == 1
    assert session["cumulative_credentials"] == 1
    assert session["cumulative_findings"] == 1


def test_ghostlog_session_history_appended_on_stop(tmp_path: Path, monkeypatch) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    start_daemon(engagement)
    _patch_ghost_extract(monkeypatch, credentials=1, findings=1)
    asyncio.run(
        process_history_lines(
            engagement,
            ["nmap -sV 10.10.10.10"],
            quiet=True,
        )
    )
    stop_daemon(engagement)

    history = _ghost_session(tmp_path)["session_history"]
    assert len(history) == 1
    assert history[0]["credentials"] == 1
    assert history[0]["findings"] == 1
    assert history[0]["commands"] == 1


def test_ghostlog_status_shows_cumulative_totals(tmp_path: Path, monkeypatch) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    start_daemon(engagement)
    _patch_ghost_extract(monkeypatch, credentials=1, findings=1)
    asyncio.run(
        process_history_lines(
            engagement,
            ["nxc smb 10.10.10.10 -u alice -p Secret123"],
            quiet=True,
        )
    )
    stop_daemon(engagement)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["log", "--status"])

    assert result.exit_code == 0, result.output
    assert "Engagement totals (all sessions):" in result.output
    assert "Credentials:     1" in result.output
    assert "Findings:        1" in result.output


def test_ghostlog_status_shows_session_history(tmp_path: Path, monkeypatch) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    start_daemon(engagement)
    _patch_ghost_extract(monkeypatch, credentials=0, findings=1)
    asyncio.run(
        process_history_lines(
            engagement,
            ["nmap -sV 10.10.10.10"],
            quiet=True,
        )
    )
    stop_daemon(engagement)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["log", "--status"])

    assert result.exit_code == 0, result.output
    assert "Session history:" in result.output
    assert "Session 1:" in result.output


def test_ghostlog_new_session_resets_current_not_cumulative(
    tmp_path: Path, monkeypatch
) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    start_daemon(engagement)
    _patch_ghost_extract(monkeypatch, credentials=1, findings=1)
    asyncio.run(
        process_history_lines(
            engagement,
            ["nxc smb 10.10.10.10 -u alice -p Secret123"],
            quiet=True,
        )
    )
    stop_daemon(engagement)
    start_daemon(engagement)

    session = _ghost_session(tmp_path)
    assert session["commands_seen"] == 0
    assert session["commands_kept"] == 0
    assert session["credentials_found"] == 0
    assert session["findings_found"] == 0
    assert session["total_sessions"] == 1
    assert session["cumulative_credentials"] == 1


def test_high_confidence_credential_written_immediately(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    extraction = GhostLogExtraction.model_validate(
        {
            "credentials": [
                {
                    "username": "alice",
                    "secret": "31d6cfe0d16ae931b73c59d7e0c089c0",
                    "secret_type": "ntlm",
                    "target": "10.10.10.10",
                }
            ]
        }
    )

    apply_extraction(engagement, extraction, source_command="secretsdump")

    data = WorkspaceStore(tmp_path).load()
    assert len(data["credentials"]) == 1
    assert data["quality_stats"]["written"] == 1


def test_low_confidence_credential_queued_not_written(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    extraction = GhostLogExtraction.model_validate(
        {
            "credentials": [
                {
                    "username": "alice",
                    "secret": "",
                    "secret_type": "plaintext",
                    "target": None,
                }
            ]
        }
    )

    apply_extraction(engagement, extraction, source_command="nxc smb")

    data = WorkspaceStore(tmp_path).load()
    assert data["credentials"] == []
    assert len(data["pending_review"]) == 1
    assert data["quality_stats"]["queued"] == 1


def test_very_low_confidence_credential_rejected(tmp_path: Path) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    extraction = GhostLogExtraction.model_validate(
        {
            "credentials": [
                {
                    "username": "",
                    "secret": "",
                    "secret_type": "plaintext",
                    "target": None,
                }
            ]
        }
    )

    apply_extraction(engagement, extraction, source_command="nxc smb")

    data = WorkspaceStore(tmp_path).load()
    assert data["credentials"] == []
    assert data["pending_review"] == []
    assert data["quality_stats"]["rejected"] == 1


def test_valid_ntlm_hash_gets_high_confidence() -> None:
    score = _validate_credential(
        {
            "username": "alice",
            "secret": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "source_host": "10.10.10.10",
        }
    )

    assert score == 1.0


def test_empty_evidence_finding_gets_low_confidence() -> None:
    score = _validate_finding(
        {
            "title": "Lateral Movement Detected",
            "affected_hosts": ["10.10.10.10"],
            "evidence": "",
        }
    )

    assert score < 0.6


def test_review_queue_populated_on_low_confidence(tmp_path: Path, monkeypatch) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    extraction = GhostLogExtraction.model_validate(
        {
            "findings": [
                {
                    "title": "Lateral Movement Detected",
                    "severity": "high",
                    "target": "10.10.10.10",
                    "evidence": "",
                }
            ]
        }
    )

    apply_extraction(engagement, extraction, source_command="nxc smb")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, ["log", "--review"], catch_exceptions=False)

    data = WorkspaceStore(tmp_path).load()
    assert len(data["pending_review"]) == 1
    assert "Pending Review" in result.output
    assert "Lateral Movement Detected" in result.output


def test_log_status_shows_quality_stats(tmp_path: Path, monkeypatch) -> None:
    engagement = init_engagement(tmp_path, "Operator", [])
    extraction = GhostLogExtraction.model_validate(
        {
            "credentials": [
                {
                    "username": "alice",
                    "secret": "31d6cfe0d16ae931b73c59d7e0c089c0",
                    "secret_type": "ntlm",
                    "target": "10.10.10.10",
                }
            ]
        }
    )
    apply_extraction(engagement, extraction, source_command="secretsdump")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["log", "--status"])

    assert result.exit_code == 0, result.output
    assert "Quality stats (this engagement):" in result.output
    assert "Written:" in result.output


def _patch_ghost_extract(monkeypatch, *, credentials: int, findings: int) -> None:
    def fake_extract_findings(
        text: str, *, model: str = "llama3"
    ) -> GhostLogExtraction:
        return GhostLogExtraction.model_validate(
            {
                "credentials": [
                    {
                        "username": f"alice{index}",
                        "secret": "Password123!",
                        "secret_type": "plaintext",
                        "target": "10.10.10.10",
                    }
                    for index in range(credentials)
                ],
                "findings": [
                    {
                        "title": f"Finding {index}",
                        "severity": "high",
                        "target": "10.10.10.10",
                        "evidence": text,
                    }
                    for index in range(findings)
                ],
            }
        )

    monkeypatch.setattr(
        "pentnote.ghostlog.daemon.extract_findings",
        fake_extract_findings,
    )


def _ghost_session(vault_root: Path) -> dict:
    return json.loads((vault_root / ".pentnote" / "ghostlog_session.json").read_text())
