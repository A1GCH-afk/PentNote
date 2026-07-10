from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from pentnote.sync.ignore import ensure_gitignore


def test_ensure_gitignore_adds_missing_entries(tmp_path: Path) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("custom-entry\n", encoding="utf-8")

    ensure_gitignore(tmp_path)

    text = gitignore.read_text(encoding="utf-8")
    assert "custom-entry" in text
    assert ".pentnote/sync-conflicts.json" in text
    assert ".pentnote/cache/" in text


def test_ensure_gitignore_write_survives_mid_write_failure(
    tmp_path: Path, monkeypatch
) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("custom-entry\n", encoding="utf-8")
    original = gitignore.read_text(encoding="utf-8")

    def boom_replace(src, dst):
        raise OSError("simulated crash mid-write")

    monkeypatch.setattr(os, "replace", boom_replace)

    with pytest.raises(OSError):
        ensure_gitignore(tmp_path)

    assert gitignore.read_text(encoding="utf-8") == original
    assert list(gitignore.parent.glob("*.tmp")) == []


def test_ensure_gitignore_write_uses_same_directory_temp_file(
    tmp_path: Path, monkeypatch
) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("custom-entry\n", encoding="utf-8")
    seen: dict[str, Path] = {}
    real_replace = os.replace

    def spy_replace(src, dst):
        seen["tmp_parent"] = Path(src).parent
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)

    ensure_gitignore(tmp_path)

    assert seen["tmp_parent"] == gitignore.parent


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_ensure_gitignore_write_preserves_permissions(tmp_path: Path) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("custom-entry\n", encoding="utf-8")
    os.chmod(gitignore, 0o640)

    ensure_gitignore(tmp_path)

    assert stat.S_IMODE(gitignore.stat().st_mode) == 0o640
