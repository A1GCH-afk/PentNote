"""Timeline note generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pentnote.generators.markdown import template_env
from pentnote.models import Finding
from pentnote.workspace.store import WorkspaceStore


def write_timeline(
    findings: list[Finding],
    output_dir: Path,
    *,
    engagement_name: str,
) -> Path:
    """Write the engagement timeline note."""

    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "01_Timeline.md"
    workspace_log = _workspace_log(output_dir)
    template = template_env().get_template("timeline.md.j2")
    path.write_text(
        template.render(
            findings=findings,
            workspace_log=workspace_log,
            engagement_name=engagement_name,
            iso_timestamp=_now_iso(),
        ),
        encoding="utf-8",
    )
    (output_dir / "TIMELINE.md").write_text(
        path.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return path


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _workspace_log(output_dir: Path) -> list[dict[str, str]]:
    root = output_dir.parent
    store = WorkspaceStore(root)
    if not store.path.exists():
        return []
    return store.get_log({})
