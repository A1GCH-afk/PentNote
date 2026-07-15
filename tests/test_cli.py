from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tomllib
from datetime import datetime
from io import BytesIO
from pathlib import Path

import pytest
from click.testing import CliRunner
from pentnote import __version__
from pentnote.cli import main
from pentnote.runner import (
    _extract_target,
    _inject_nmap_xml,
    _make_raw_path,
    _nmap_args_for_raw_xml,
    _run_and_capture,
    _write_raw_text,
)

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class _FakeProcess:
    def __init__(self, lines: list[str], returncode: int = 0) -> None:
        self.stdout = BytesIO("".join(lines).encode())
        self._returncode = returncode

    def wait(self) -> int:
        return self._returncode


class _InterruptingStream:
    def read(self, _size: int = -1) -> bytes:
        raise KeyboardInterrupt


class _InterruptingProcess:
    def __init__(self) -> None:
        self.stdout = _InterruptingStream()
        self.terminated = False

    def wait(self, timeout=None) -> int:
        return 130

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.terminated = True


def _mock_popen(monkeypatch, output: str, commands: list[list[str]]) -> None:
    def fake_popen(command, **_kwargs):
        commands.append(list(command))
        return _FakeProcess(output.splitlines(keepends=True))

    monkeypatch.setattr("pentnote.runner.subprocess.Popen", fake_popen)


def _mock_nmap_popen(
    monkeypatch,
    terminal_output: str,
    xml_output: str,
    commands: list[list[str]],
) -> None:
    def fake_popen(command, **_kwargs):
        commands.append(list(command))
        if "-oX" in command:
            raw_path = Path(command[command.index("-oX") + 1])
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(xml_output, encoding="utf-8")
        return _FakeProcess(terminal_output.splitlines(keepends=True))

    monkeypatch.setattr("pentnote.runner.subprocess.Popen", fake_popen)


def test_cli_init_prints_all_workspace_directories() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "Abd", "--output", "Abd"])

        assert result.exit_code == 0, result.output
        assert "Notes:" in result.output
        assert "Reports:" in result.output
        assert "Raw:" in result.output
        assert "State:" in result.output
        assert Path("Abd/notes").exists()
        assert Path("Abd/reports").exists()
        assert Path("Abd/raw").exists()
        assert Path("Abd/.pentnote").exists()


def test_version_in_status_output() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        init_result = runner.invoke(main, ["init", "Client", "--scope", "10.0.0.1"])
        assert init_result.exit_code == 0, init_result.output

        result = runner.invoke(main, ["status"])

    assert result.exit_code == 0, result.output
    assert "PentNote v1.1.0" in result.output


def test_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())

    assert pyproject["project"]["version"] == __version__ == "1.1.0"


def test_version_flag_outputs_version() -> None:
    result = CliRunner().invoke(main, ["--version"])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == "pentnote 1.1.0"


def test_changelog_documents_current_release() -> None:
    changelog = (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert "## [1.0.0] - 2026-07-02" in changelog
    assert "Consolidated the CLI to 12 focused top-level commands." in changelog
    assert "## [1.1.0] - 2026-07-13" in changelog


def test_publish_workflow_requires_manual_confirmation() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )

    assert "Publish to PyPI" in workflow
    assert "workflow_dispatch" in workflow
    assert "tags:" not in workflow
    assert "TWINE_PASSWORD" in workflow


def test_ci_workflow_runs_supported_python_matrix() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert 'python-version: ["3.11", "3.12", "3.13"]' in workflow
    assert "ubuntu-latest" in workflow
    assert "macos-latest" in workflow


def test_readme_describes_public_parser_count() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Supported Parsers" in readme
    assert "PentNote ships with 27 parser strategies" in readme
    assert "WinPEAS" in readme
    assert "LinPEAS" in readme


def test_readme_structure_includes_all_required_sections() -> None:
    assert not (PROJECT_ROOT / "docs").exists()
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    for heading in (
        "## Overview",
        "## Installation",
        "## Quickstart",
        "## Command Reference",
        "## Example Workflow",
        "## MITRE ATT&CK Integration",
        "## Reports",
        "## Git Sync & Vault Structure",
        "## AI Assistant",
        "## Extending PentNote",
        "## Troubleshooting",
        "## Contributing, License, Security",
    ):
        assert heading in readme


def test_plugin_guide_documents_entry_point() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert '[project.entry-points."pentnote.parsers"]' in readme
    assert "AbstractParser" in readme


def test_plugin_example_is_installable_package() -> None:
    pyproject = tomllib.loads(
        (PROJECT_ROOT / "examples" / "plugin_example" / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )

    assert pyproject["project"]["name"] == "pentnote-myscanner-plugin"
    assert (
        pyproject["project"]["entry-points"]["pentnote.parsers"]["myscanner"]
        == "myparser.parser:MyScannerParser"
    )


def test_cli_parse_nmap_writes_host_note() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "parse",
                str(FIXTURES / "nmap_sample.xml"),
                "--output",
                "vault",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Parser: nmap" in result.output
        assert Path("vault/hosts/10-129-48-183.md").exists()


def test_cli_parse_nmap_text_from_stdin_writes_host_note() -> None:
    runner = CliRunner()
    nmap_text = """Starting Nmap 7.94SVN ( https://nmap.org )
Nmap scan report for 10.129.48.183
Host is up (0.042s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10

Nmap done: 1 IP address (1 host up) scanned in 5.00 seconds
"""

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["parse", "--tool", "nmap", "--output", "vault"],
            input=nmap_text,
        )

        assert result.exit_code == 0, result.output
        assert "Parser: nmap" in result.output
        assert Path("vault/hosts/10-129-48-183.md").exists()


def test_run_saves_raw_file(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_nmap_popen(
        monkeypatch,
        "Starting Nmap\nNmap scan report for 10.129.48.183\n",
        (FIXTURES / "nmap_sample.xml").read_text(),
        commands,
    )

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["run", "nmap", "-sV", "10.129.48.183"])

        assert result.exit_code == 0, result.output
        raw_files = list(Path("raw/nmap").glob("*-10.129.48.183.xml"))
        assert raw_files
        assert "saved:" in result.output


def test_run_creates_notes_after_parse(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_nmap_popen(
        monkeypatch,
        "Starting Nmap\nNmap scan report for 10.129.48.183\n",
        (FIXTURES / "nmap_sample.xml").read_text(),
        commands,
    )

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["run", "nmap", "-sV", "10.129.48.183"])

        assert result.exit_code == 0, result.output
        assert Path("notes/hosts/10-129-48-183.md").exists()


def test_run_nmap_injects_xml_flag() -> None:
    assert _inject_nmap_xml(["-sV", "10.10.10.10"]) == [
        "-sV",
        "10.10.10.10",
        "-oX",
        "-",
    ]


def test_run_nmap_no_duplicate_xml_flag() -> None:
    assert _inject_nmap_xml(["-sV", "10.10.10.10", "-oX", "scan.xml"]) == [
        "-sV",
        "10.10.10.10",
        "-oX",
        "scan.xml",
    ]


def test_run_nmap_writes_xml_file_but_streams_normal_output(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_nmap_popen(
        monkeypatch,
        "Starting Nmap\nNmap scan report for 10.129.48.183\n",
        (FIXTURES / "nmap_sample.xml").read_text(),
        commands,
    )

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["run", "nmap", "-sV", "10.129.48.183"])

        assert result.exit_code == 0, result.output
        assert "Starting Nmap" in result.output
        assert "<?xml" not in result.output
        assert list(Path("raw/nmap").glob("*-10.129.48.183.txt"))
        assert commands[0][-2] == "-oX"
        assert commands[0][-1].endswith(".xml")


def test_run_nmap_saves_human_readable_output_file(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_nmap_popen(
        monkeypatch,
        "Starting Nmap\nNmap scan report for 10.129.48.183\n",
        (FIXTURES / "nmap_sample.xml").read_text(),
        commands,
    )

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["run", "nmap", "-sV", "10.129.48.183"])

        assert result.exit_code == 0, result.output
        text_files = list(Path("raw/nmap").glob("*-10.129.48.183.txt"))
        assert text_files
        assert "Nmap scan report" in text_files[0].read_text()
        assert f"saved:  {Path.cwd() / text_files[0]}" in result.output


def test_run_nmap_replaces_stdout_xml_with_raw_file_path() -> None:
    args = _nmap_args_for_raw_xml(
        ["-sV", "10.10.10.10", "-oX", "-"],
        Path("raw/nmap/scan.xml"),
    )

    assert args == ["-sV", "10.10.10.10", "-oX", "raw/nmap/scan.xml"]


def test_run_streams_carriage_return_progress(monkeypatch, capsys) -> None:
    commands: list[list[str]] = []
    output = "Starting gobuster\nProgress: 529 / 17576 (3.01%)\r"
    _mock_popen(monkeypatch, output, commands)

    captured, returncode = _run_and_capture(["gobuster", "vhost"])
    terminal = capsys.readouterr().out

    assert returncode == 0
    assert "\r" in terminal
    assert "Progress: 529 / 17576" in terminal
    assert captured == output


def test_run_capture_handles_keyboard_interrupt(monkeypatch) -> None:
    proc = _InterruptingProcess()

    def fake_popen(command, **_kwargs):
        return proc

    monkeypatch.setattr("pentnote.runner.subprocess.Popen", fake_popen)

    captured, returncode = _run_and_capture(["evil-winrm", "-i", "winterfell"])

    assert captured == ""
    assert returncode == 130
    assert proc.terminated is True


def test_run_evilwinrm_uses_specific_parser_and_folder(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_popen(
        monkeypatch,
        (FIXTURES / "evilwinrm_sample.txt").read_text(),
        commands,
    )

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "run",
                "evil-winrm",
                "-u",
                "robb.stark",
                "-p",
                "sexywolfy",
                "-i",
                "winterfell",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "parser: evil-winrm" in result.output
        assert list(Path("raw/evil-winrm").glob("*-winterfell.txt"))
        assert list(Path("notes/findings/evil-winrm").glob("*.md"))
        assert not Path("notes/findings/universal").exists()


def test_run_writes_command_header_to_raw_file(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_popen(monkeypatch, "found /admin (Status: 200)\n", commands)

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["run", "gobuster", "-u", "http://t/", "dir"])

        assert result.exit_code == 0, result.output
        raw = list(Path("raw/gobuster").glob("*.txt"))[0].read_text()
        assert raw.startswith("# Command: gobuster -u http://t/ dir")
        assert "found /admin (Status: 200)" in raw


def test_run_non_interactive_raw_preserves_ansi(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    # A TTY-adaptive tool's colour codes must survive byte-for-byte after the
    # header line -- only interactive shells get stripped.
    _mock_popen(monkeypatch, "\x1b[32m/admin\x1b[0m (Status: 200)\n", commands)

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["run", "gobuster", "-u", "http://t/", "dir"])

        assert result.exit_code == 0, result.output
        raw = list(Path("raw/gobuster").glob("*.txt"))[0].read_text()
        assert "\x1b[32m" in raw


def test_run_evilwinrm_strips_ansi_from_raw_file(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_popen(
        monkeypatch,
        (FIXTURES / "evilwinrm_ansi_capture.txt").read_text(),
        commands,
    )

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["run", "evil-winrm", "-i", "10.0.0.1", "-u", "svc_health$"],
        )

        assert result.exit_code == 0, result.output
        raw = list(Path("raw/evil-winrm").glob("*.txt"))[0].read_text()
        assert raw.startswith("# Command: evil-winrm -i 10.0.0.1 -u")
        assert "\x1b" not in raw
        assert "\x01" not in raw
        assert "net user svc_health" in raw
        # The tab-completion redraw collapses to a single readable command line.
        assert "> whoami" in raw


def test_run_unknown_tool_records_in_host_note(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_popen(monkeypatch, "hydra v9 starting\n", commands)

    with runner.isolated_filesystem():
        init_result = runner.invoke(main, ["init", "Client", "--scope", "10.0.0.7"])
        assert init_result.exit_code == 0, init_result.output

        result = runner.invoke(main, ["run", "hydra", "-l", "admin", "10.0.0.7", "ssh"])

        assert result.exit_code == 0, result.output
        note = Path("notes/hosts/10-0-0-7.md").read_text()
        assert "## Unparsed / Unsupported Tools" in note
        assert "hydra" in note
        assert "hydra -l admin 10.0.0.7 ssh" in note


def test_run_unknown_tool_uses_universal(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_popen(
        monkeypatch, "Hydra scan against 10.0.0.1 found CVE-2024-12345\n", commands
    )

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["run", "hydra", "-l", "admin", "-P", "pass.txt", "10.0.0.1", "ssh"],
        )

        assert result.exit_code == 0, result.output
        assert "parser: universal" in result.output
        assert list(Path("raw/hydra").glob("*-10.0.0.1.txt"))


def test_run_no_parse_skips_notes(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_nmap_popen(
        monkeypatch,
        "Starting Nmap\nNmap scan report for 10.129.48.183\n",
        (FIXTURES / "nmap_sample.xml").read_text(),
        commands,
    )

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["run", "nmap", "-sV", "10.129.48.183", "--no-parse"],
        )

        assert result.exit_code == 0, result.output
        assert list(Path("raw/nmap").glob("*-10.129.48.183.xml"))
        assert not Path("notes").exists()


def test_run_no_universal_skips_parse_for_unknown_tool(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_popen(monkeypatch, "Hydra noisy output\n", commands)

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["run", "hydra", "10.0.0.1", "ssh", "--no-universal"],
        )

        assert result.exit_code == 0, result.output
        assert "raw saved only" in result.output
        assert "parser:" not in result.output
        assert not Path("notes").exists()


def test_run_no_universal_still_saves_raw(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_popen(monkeypatch, "Hydra noisy output\n", commands)

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["run", "hydra", "10.0.0.1", "ssh", "--no-universal"],
        )

        assert result.exit_code == 0, result.output
        assert list(Path("raw/hydra").glob("*-10.0.0.1.txt"))


def test_write_raw_text_writes_header_and_body(tmp_path: Path) -> None:
    path = tmp_path / "raw" / "hydra" / "capture.txt"

    _write_raw_text(path, "Hydra output\n", ["hydra", "-l", "admin"])

    text = path.read_text(encoding="utf-8")
    assert text.startswith("# Command: hydra -l admin\n")
    assert "Hydra output" in text


def test_write_raw_text_survives_mid_write_failure(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "raw" / "hydra" / "capture.txt"
    path.parent.mkdir(parents=True)
    original = "# Command: hydra old\nold output\n"
    path.write_text(original, encoding="utf-8")

    def boom_replace(src, dst):
        raise OSError("simulated crash mid-write")

    monkeypatch.setattr(os, "replace", boom_replace)

    with pytest.raises(OSError):
        _write_raw_text(path, "new output\n", ["hydra", "new"])

    assert path.read_text(encoding="utf-8") == original
    assert list(path.parent.glob("*.tmp")) == []


def test_write_raw_text_uses_same_directory_temp_file(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "raw" / "hydra" / "capture.txt"
    seen: dict[str, Path] = {}
    real_replace = os.replace

    def spy_replace(src, dst):
        seen["tmp_parent"] = Path(src).parent
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)

    _write_raw_text(path, "output\n", ["hydra"])

    assert seen["tmp_parent"] == path.parent


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_write_raw_text_preserves_permissions(tmp_path: Path) -> None:
    path = tmp_path / "raw" / "hydra" / "capture.txt"
    path.parent.mkdir(parents=True)
    path.write_text("old\n", encoding="utf-8")
    os.chmod(path, 0o640)

    _write_raw_text(path, "new output\n", ["hydra"])

    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_run_nmap_xml_fallback_write_survives_mid_write_failure(
    tmp_path: Path, monkeypatch
) -> None:
    from pentnote.runner import _run_nmap_and_capture_xml

    raw_path = tmp_path / "raw" / "nmap" / "scan.xml"
    raw_path.parent.mkdir(parents=True)

    def fake_popen(command, **_kwargs):
        # Simulate nmap being killed before it writes its own -oX output.
        return _FakeProcess(["Starting Nmap\n"])

    monkeypatch.setattr("pentnote.runner.subprocess.Popen", fake_popen)

    real_replace = os.replace
    calls = {"count": 0}

    def fail_second_replace(src, dst):
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("simulated crash mid-write")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", fail_second_replace)

    with pytest.raises(OSError):
        _run_nmap_and_capture_xml("nmap", ["-sV", "10.10.10.10"], raw_path)

    # The .txt companion (written first) succeeded; the .xml fallback (second
    # write, simulated crash) must leave no trace -- no half-written raw_path,
    # no leftover temp file.
    assert not raw_path.exists()
    assert list(raw_path.parent.glob("*.tmp")) == []


def test_run_quiet_suppresses_output(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    _mock_popen(
        monkeypatch, "Hydra scan against 10.0.0.1 found CVE-2024-12345\n", commands
    )

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["run", "hydra", "-q", "10.0.0.1", "ssh", "--no-universal"],
        )

        assert result.exit_code == 0, result.output
        assert "Hydra scan against" not in result.output
        assert "saved:" in result.output


def test_run_quiet_still_writes_notes(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    output = "Gobuster v3.8.2\n/admin (Status: 200) [Size: 1024]\n"
    _mock_popen(monkeypatch, output, commands)

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "run",
                "gobuster",
                "-q",
                "dir",
                "-u",
                "http://target.htb",
                "-w",
                "words.txt",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "Gobuster v3.8.2" not in result.output
        assert list(Path("notes/findings/gobuster").glob("*.md"))


def test_run_parser_override(monkeypatch) -> None:
    runner = CliRunner()
    commands: list[list[str]] = []
    output = "Gobuster v3.8.2\n/admin (Status: 200) [Size: 1024]\n"
    _mock_popen(monkeypatch, output, commands)

    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "run",
                "--tool",
                "gobuster",
                "ffuf",
                "-u",
                "http://target.htb/FUZZ",
                "-w",
                "words.txt",
            ],
        )

        assert result.exit_code == 0, result.output
        assert "parser: gobuster" in result.output
        assert list(Path("raw/ffuf").glob("*-target.htb-FUZZ.txt"))


def test_run_target_extraction_url() -> None:
    assert _extract_target("gobuster", ["dir", "-u", "http://kobold.htb"]) == (
        "kobold.htb"
    )


def test_run_target_extraction_ip() -> None:
    assert _extract_target("nmap", ["-sV", "-p", "22,80", "10.10.10.10"]) == (
        "10.10.10.10"
    )


def test_run_raw_path_includes_timestamp(tmp_path: Path, monkeypatch) -> None:
    class FixedDateTime:
        @classmethod
        def now(cls):
            return datetime(2026, 5, 4, 14, 23)

    monkeypatch.setattr("pentnote.runner.datetime", FixedDateTime)

    path = _make_raw_path(
        tmp_path,
        "nmap",
        {"raw_subdir": "nmap", "raw_ext": ".xml"},
        "10.10.10.10",
    )

    assert re.fullmatch(r"20260504-1423-10\.10\.10\.10\.xml", path.name)


def test_cli_parse_missing_file_returns_click_error() -> None:
    runner = CliRunner()

    result = runner.invoke(main, ["parse", "scans/nmap.xml"])

    assert result.exit_code != 0
    assert "Could not open file" in result.output
    assert "scans/nmap.xml" in result.output


def test_cli_engagement_flow_and_mitre_commands() -> None:
    runner = CliRunner()
    cme_content = (FIXTURES / "cme_sample.txt").read_text()

    with runner.isolated_filesystem():
        assert (
            runner.invoke(
                main,
                ["init", "Client_2026", "--scope", "192.168.56.0/24"],
            ).exit_code
            == 0
        )

        parse_result = runner.invoke(
            main,
            ["parse", "-", "--tool", "cme"],
            input=cme_content,
        )
        assert parse_result.exit_code == 0, parse_result.output
        assert "Parser: crackmapexec" in parse_result.output

        for command in (
            ["sync", "--reindex"],
            ["log", "--timeline"],
            ["mitre", "show"],
        ):
            result = runner.invoke(main, command)
            assert result.exit_code == 0, result.output

        assert "T1557.001" in runner.invoke(main, ["mitre", "show"]).output
        assert "Credential Access" in runner.invoke(main, ["mitre", "coverage"]).output
        assert runner.invoke(main, ["mitre", "next"]).exit_code == 0
        assert runner.invoke(main, ["mitre", "chains"]).exit_code == 0

        report = runner.invoke(main, ["report", "--format", "both", "--with-defenses"])
        assert report.exit_code == 0, report.output
        export = runner.invoke(main, ["mitre", "export", "--format", "navigator"])
        assert export.exit_code == 0, export.output
        assert Path("reports/layer.json").exists()


def test_cli_status_uses_tables() -> None:
    runner = CliRunner()
    cme_content = (FIXTURES / "cme_sample.txt").read_text()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        runner.invoke(main, ["parse", "-", "--tool", "cme"], input=cme_content)

        result = runner.invoke(main, ["status"])

        assert result.exit_code == 0, result.output
        assert "PentNote Status" in result.output
        assert "Severity Breakdown" in result.output
        assert "Credentials" in result.output


def test_cli_status_check_merges_flags_and_clears() -> None:
    runner = CliRunner()
    host_a = (
        "SMB  192.168.56.10  445  SRV01  "
        "[*] Windows Server 2019 x64 (name:SRV01) (domain:LAB) (signing:False)\n"
    )
    host_b = (
        "SMB  192.168.56.20  445  SRV01  "
        "[*] Windows Server 2019 x64 (name:SRV01) (domain:LAB) (signing:False)\n"
    )

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])

        # Clean vault: no name collisions -> check passes.
        runner.invoke(main, ["parse", "-", "--tool", "cme"], input=host_a)
        clean = runner.invoke(main, ["status", "--health", "--check-merges"])
        assert clean.exit_code == 0, clean.output
        assert "host-merge check: no name collisions" in clean.output

        # A second, different host reusing the SRV01 name at another IP -> flagged.
        runner.invoke(main, ["parse", "-", "--tool", "cme"], input=host_b)
        flagged = runner.invoke(main, ["status", "--health", "--check-merges"])
        assert flagged.exit_code == 0, flagged.output
        assert "share a name with another host but no IP link" in flagged.output
        assert "[HIGH]" in flagged.output
        assert "Read-only" in flagged.output

        # Default --health (without the flag) does not run the merge check.
        plain = runner.invoke(main, ["status", "--health"])
        assert "host-merge check" not in plain.output


def test_cli_recursive_parse_and_error_paths() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("inputs").mkdir()
        Path("inputs/cme.txt").write_text((FIXTURES / "cme_sample.txt").read_text())
        Path("inputs/nmap.xml").write_text((FIXTURES / "nmap_sample.xml").read_text())

        without_recursive = runner.invoke(main, ["parse", "inputs"])
        assert without_recursive.exit_code != 0

        recursive = runner.invoke(
            main,
            ["parse", "inputs", "--recursive", "--output", "vault"],
        )
        assert recursive.exit_code == 0, recursive.output
        assert recursive.output.count("Parser:") == 2

        unknown = runner.invoke(main, ["parse", "inputs/cme.txt", "--tool", "missing"])
        assert unknown.exit_code != 0
        assert "Unknown parser" in unknown.output


def test_cli_recursive_parse_continues_after_bad_file() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("inputs").mkdir()
        Path("inputs/nmap.xml").write_text((FIXTURES / "nmap_sample.xml").read_text())
        Path("inputs/bad.txt").write_text("")

        result = runner.invoke(
            main,
            ["parse", "inputs", "--recursive", "--output", "vault"],
        )

        assert result.exit_code != 0
        assert "Parser: nmap" in result.output
        assert "bad.txt" in result.output


def test_cli_parser_discovery_commands() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        # No engagement vault initialized: --parsers/--parsers-detect must not
        # require one, matching the standalone `parsers` command they replace.
        list_result = runner.invoke(main, ["status", "--parsers"])
        detect_result = runner.invoke(
            main,
            ["status", "--parsers-detect", str(FIXTURES / "nmap_sample.xml")],
        )

        assert list_result.exit_code == 0, list_result.output
        assert "nmap" in list_result.output
        assert detect_result.exit_code == 0, detect_result.output
        assert "nmap:" in detect_result.output


def test_cli_ai_summary_requires_optional_dependency() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("nmap.xml").write_text((FIXTURES / "nmap_sample.xml").read_text())
        result = runner.invoke(main, ["parse", "nmap.xml", "--ai-summary"])

    assert result.exit_code != 0
    assert "pentnote[operator]" in result.output


def test_doctor_fix_adds_local_json_to_gitignore() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        gitignore = Path(".gitignore")
        gitignore.write_text(
            "\n".join(
                line
                for line in gitignore.read_text(encoding="utf-8").splitlines()
                if line != ".pentnote/local.json"
            )
            + "\n",
            encoding="utf-8",
        )

        result = runner.invoke(main, ["status", "--health", "--fix"])

        assert result.exit_code == 0, result.output
        assert ".pentnote/local.json" in gitignore.read_text(encoding="utf-8")


def test_doctor_fix_repairs_workspace_permissions() -> None:
    if os.name == "nt":
        return
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        workspace = Path(".pentnote/workspace.json")
        workspace.write_text(
            json.dumps({"credentials": [], "notes": [], "loot": [], "log": []}) + "\n",
            encoding="utf-8",
        )
        os.chmod(workspace, 0o644)

        result = runner.invoke(main, ["status", "--health", "--fix"])

        assert result.exit_code == 0, result.output
        assert workspace.stat().st_mode & 0o777 == 0o600


def test_doctor_fix_dry_run_makes_no_changes() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        gitignore = Path(".gitignore")
        gitignore.write_text(".pentnote/workspace.json\n", encoding="utf-8")

        result = runner.invoke(main, ["status", "--health", "--fix", "--dry-run"])

        assert result.exit_code == 0, result.output
        assert "Would fix:" in result.output
        assert ".pentnote/local.json" not in gitignore.read_text(encoding="utf-8")


def test_doctor_fix_backs_up_corrupt_findings() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        findings = Path(".pentnote/findings.json")
        findings.write_text("{not-json", encoding="utf-8")

        result = runner.invoke(main, ["status", "--health", "--fix"])

        assert result.exit_code == 0, result.output
        assert json.loads(findings.read_text(encoding="utf-8")) == []
        assert list(Path(".pentnote").glob("findings.json.corrupt.*"))


def test_doctor_fix_findings_reset_leaves_no_leftover_temp_on_write_failure(
    monkeypatch,
) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        findings = Path(".pentnote/findings.json")
        findings.write_text("{not-json", encoding="utf-8")

        def boom(*args, **kwargs):
            raise OSError("simulated crash mid-write")

        monkeypatch.setattr("pentnote.cli.atomic_write_json", boom)

        result = runner.invoke(main, ["status", "--health", "--fix"])

        assert result.exit_code != 0
        assert list(Path(".pentnote").glob("*.tmp")) == []


def test_doctor_fix_skips_low_by_default() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        finding_dir = Path("notes/findings")
        finding_dir.mkdir(parents=True)
        orphan = finding_dir / "deadbeef-old.md"
        orphan.write_text("# old\n", encoding="utf-8")

        result = runner.invoke(main, ["status", "--health", "--fix"])

        assert result.exit_code == 0, result.output
        assert "Skipped" in result.output
        assert orphan.exists()


def test_doctor_fix_include_low_cleans_orphans() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        finding_dir = Path("notes/findings")
        finding_dir.mkdir(parents=True)
        orphan = finding_dir / "deadbeef-old.md"
        orphan.write_text("# old\n", encoding="utf-8")

        result = runner.invoke(main, ["status", "--health", "--fix", "--include-low"])

        assert result.exit_code == 0, result.output
        assert not orphan.exists()


def test_status_health_bare_shows_issues_without_fixing() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        gitignore = Path(".gitignore")
        gitignore.write_text(
            "\n".join(
                line
                for line in gitignore.read_text(encoding="utf-8").splitlines()
                if line != ".pentnote/local.json"
            )
            + "\n",
            encoding="utf-8",
        )

        result = runner.invoke(main, ["status", "--health"])

        assert result.exit_code == 0, result.output
        assert "run pentnote status --health --fix" in result.output
        assert ".pentnote/local.json" not in gitignore.read_text(encoding="utf-8")


def test_sync_reindex_standalone_skips_git(tmp_path: Path) -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])

        result = runner.invoke(main, ["sync", "--reindex"])

        assert result.exit_code == 0, result.output
        assert "wrote:" in result.output
        assert Path("notes/00_Index.md").exists()


def test_sync_graph_requires_bloodhound_json() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])

        result = runner.invoke(main, ["sync", "--graph"])

        assert result.exit_code != 0
        assert "--bloodhound-json" in result.output


def test_sync_graph_standalone_skips_git() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])

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
        assert Path("paths.canvas").exists()


def test_sync_bare_auto_triggers_reindex_and_git_sync() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        runner.invoke(main, ["init", "Client_2026"])
        subprocess.run(["git", "init", "-q"], check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "config", "user.name", "Test"], check=True)

        result = runner.invoke(main, ["sync"])

        assert result.exit_code == 0, result.output
        assert Path("notes/00_Index.md").exists()
        assert "Sync completed" in result.output or "sync" in result.output.lower()
