from __future__ import annotations

from pathlib import Path

from pentnote.core.terminal import strip_interactive_noise

FIXTURES = Path(__file__).parent / "fixtures"


def test_strip_removes_all_control_bytes() -> None:
    raw = (FIXTURES / "evilwinrm_ansi_capture.txt").read_text()

    clean = strip_interactive_noise(raw)

    assert "\x1b" not in clean
    assert "\x01" not in clean
    assert "\x02" not in clean


def test_strip_collapses_tab_completion_redraw() -> None:
    raw = (FIXTURES / "evilwinrm_ansi_capture.txt").read_text()

    clean = strip_interactive_noise(raw)

    # The character-by-character "whoami" redraw resolves to a single clean line.
    assert "*Evil-WinRM* PS C:\\Users\\svc_health$\\Documents> whoami" in clean
    assert "wwhwho" not in clean  # smeared redraw prefix must be gone


def test_strip_preserves_command_output() -> None:
    raw = (FIXTURES / "evilwinrm_ansi_capture.txt").read_text()

    clean = strip_interactive_noise(raw)

    assert "corp\\svc_health" in clean
    assert "User name                    svc_health" in clean
    assert "Global Group memberships     *Domain Users" in clean
    assert "The command completed successfully." in clean


def test_strip_column_jump_overwrites_in_place() -> None:
    # CSI nG (CHA) moves the cursor to an absolute column; later text overwrites.
    text = "upload old\x1b[1Gupload new\n"

    assert strip_interactive_noise(text) == "upload new\n"


def test_strip_carriage_return_progress_keeps_final_frame() -> None:
    text = "Progress: 10%\rProgress: 55%\rProgress: 100%\n"

    assert strip_interactive_noise(text) == "Progress: 100%\n"


def test_strip_erase_line_clears_buffer() -> None:
    # Carriage return resets the column, then EL(2) wipes the stale content.
    text = "stale content\r\x1b[2Kfresh\n"

    assert strip_interactive_noise(text) == "fresh\n"


def test_strip_is_noop_on_plain_text() -> None:
    text = "line one\nline two\n"

    assert strip_interactive_noise(text) == text
