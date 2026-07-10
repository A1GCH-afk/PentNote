from __future__ import annotations

from pathlib import Path

import pytest
from pentnote.core.fileio import atomic_write_text


def test_atomic_write_text_writes_content_and_cleans_up_temp(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "note.md"

    atomic_write_text(path, "hello\n")

    assert path.read_text() == "hello\n"
    assert not (path.parent / f"{path.name}.tmp").exists()


def test_atomic_write_text_uses_temp_then_rename(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "note.md"
    path.write_text("original\n", encoding="utf-8")
    seen: dict[str, str] = {}
    real_replace = Path.replace

    def spy_replace(self: Path, target) -> Path:
        seen["tmp"] = self.name
        seen["target"] = Path(target).name
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", spy_replace)

    atomic_write_text(path, "new\n")

    assert seen["tmp"] == "note.md.tmp"  # wrote to a sibling temp file
    assert seen["target"] == "note.md"  # then renamed onto the target
    assert path.read_text() == "new\n"


def test_atomic_write_text_leaves_original_intact_on_interrupted_rename(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "note.md"
    path.write_text("ORIGINAL COMPLETE CONTENT\n", encoding="utf-8")

    def boom_replace(self: Path, target) -> Path:
        raise OSError("simulated crash during rename")

    monkeypatch.setattr(Path, "replace", boom_replace)

    with pytest.raises(OSError):
        atomic_write_text(path, "half-written garbage")

    # The target is never truncated: readers still see the old complete file.
    assert path.read_text() == "ORIGINAL COMPLETE CONTENT\n"
