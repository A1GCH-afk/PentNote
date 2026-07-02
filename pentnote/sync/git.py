"""Git synchronization orchestration for collaboration mode."""

from __future__ import annotations

from pathlib import Path

from pentnote.core.models import PentNoteModel
from pentnote.sync.conflicts import log_conflicts
from pentnote.sync.ignore import ensure_gitignore, warn_if_sensitive_paths_not_ignored


class SyncResult(PentNoteModel):
    """Summary of a sync attempt."""

    committed: bool
    pushed: bool
    conflicts: list[str]
    message: str


def sync_once(root: Path, *, remote: str = "origin", branch: str = "") -> SyncResult:
    """Pull, commit, and push vault changes."""

    try:
        import git  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "Install PentNote with pentnote[operator] to use sync."
        ) from exc

    try:
        from filelock import FileLock
    except ImportError:
        FileLock = None

    warn_if_sensitive_paths_not_ignored(root)
    ensure_gitignore(root)
    if FileLock is None:
        return _sync_once_unlocked(root, remote=remote, branch=branch)
    lock_path = root / ".pentnote" / "sync.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with FileLock(lock_path):
        return _sync_once_unlocked(root, remote=remote, branch=branch)


def _sync_once_unlocked(root: Path, *, remote: str, branch: str) -> SyncResult:
    from git import GitCommandError, Repo

    repo = Repo(root)
    if repo.bare:
        raise RuntimeError("Vault path is a bare Git repository.")

    try:
        if repo.remotes:
            pull_ref = f"{remote} {branch}".strip()
            repo.git.pull("--rebase", *pull_ref.split())
    except GitCommandError:
        conflicts = sorted(repo.index.unmerged_blobs().keys())
        log_conflicts(root, conflicts)
        return SyncResult(False, False, conflicts, "Pull/rebase reported conflicts.")

    if repo.is_dirty(untracked_files=True):
        repo.git.add(A=True)
        repo.index.commit("pentnote sync")
        committed = True
    else:
        committed = False

    pushed = False
    try:
        if repo.remotes:
            args = [remote]
            if branch:
                args.append(branch)
            repo.git.push(*args)
            pushed = True
    except GitCommandError as exc:
        return SyncResult(committed, False, [], f"Commit completed, push failed: {exc}")
    return SyncResult(committed, pushed, [], "Sync completed.")
