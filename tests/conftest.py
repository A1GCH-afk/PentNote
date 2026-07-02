from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests away from the real ~/.pentnote tree."""

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
