from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from pentnote.core.fileio import atomic_write_json, atomic_write_text


def test_atomic_write_text_writes_content_and_cleans_up_temp(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "note.md"

    atomic_write_text(path, "hello\n")

    assert path.read_text() == "hello\n"
    assert list(path.parent.glob("*.tmp")) == []


def test_atomic_write_text_uses_same_directory_temp_file(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "note.md"
    path.write_text("original\n", encoding="utf-8")
    seen: dict[str, Path] = {}
    real_replace = os.replace

    def spy_replace(src, dst):
        seen["tmp_parent"] = Path(src).parent
        seen["tmp_name"] = Path(src).name
        seen["target"] = Path(dst)
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)

    atomic_write_text(path, "new\n")

    assert seen["tmp_parent"] == tmp_path  # temp file lived beside the target
    assert "note.md" in seen["tmp_name"]  # clearly identifiable temp name
    assert seen["tmp_name"] != "note.md"
    assert seen["target"] == path
    assert path.read_text() == "new\n"


def test_atomic_write_text_temp_names_do_not_collide_across_writers(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "note.md"
    seen_names: set[str] = set()
    real_replace = os.replace

    def spy_replace(src, dst):
        seen_names.add(Path(src).name)
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)

    for _ in range(5):
        atomic_write_text(path, "content\n")

    assert len(seen_names) == 5  # each write picked a distinct temp filename


def test_atomic_write_text_leaves_original_intact_on_interrupted_write(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "note.md"
    path.write_text("ORIGINAL COMPLETE CONTENT\n", encoding="utf-8")

    def boom_replace(src, dst):
        raise OSError("simulated crash before rename")

    monkeypatch.setattr(os, "replace", boom_replace)

    with pytest.raises(OSError):
        atomic_write_text(path, "half-written garbage")

    # The target is never truncated: readers still see the old complete file.
    assert path.read_text() == "ORIGINAL COMPLETE CONTENT\n"
    # And no leftover temp file remains in the directory.
    assert list(path.parent.glob("*.tmp")) == []


def test_atomic_write_text_leaves_no_temp_file_when_write_itself_fails(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "note.md"
    path.write_text("ORIGINAL\n", encoding="utf-8")
    real_fdopen = os.fdopen

    def boom_fdopen(fd, *args, **kwargs):
        handle = real_fdopen(fd, *args, **kwargs)

        def boom_write(_text):
            raise OSError("simulated disk full")

        handle.write = boom_write
        return handle

    monkeypatch.setattr(os, "fdopen", boom_fdopen)

    with pytest.raises(OSError):
        atomic_write_text(path, "new content")

    assert path.read_text() == "ORIGINAL\n"
    assert list(path.parent.glob("*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_atomic_write_text_preserves_original_file_permissions(tmp_path: Path) -> None:
    path = tmp_path / "note.md"
    path.write_text("original\n", encoding="utf-8")
    os.chmod(path, 0o640)

    atomic_write_text(path, "new\n")

    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_atomic_write_json_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "state.json"

    atomic_write_json(path, {"a": 1, "b": [1, 2, 3]})

    assert path.read_text().endswith("\n")
    assert json.loads(path.read_text()) == {"a": 1, "b": [1, 2, 3]}
