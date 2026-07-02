# Contributing

Thanks for your interest in improving PentNote. This guide covers local setup,
the quality gate, commit and branch conventions, and the stability policy for
the CLI and parsers.

## Local Setup

```bash
python3 -m pip install -e ".[dev]"
```

For the optional operator features (graph layout, screenshots, Git sync, and
Ghost Log), also install the `operator` extra:

```bash
python3 -m pip install -e ".[dev,operator]"
```

## Quality Gate

Run these checks, in this order, before every commit. Do not commit if the
test suite fails:

```bash
ruff check .
black --check .
mypy .
pytest
```

- `ruff` and `black` must pass cleanly.
- The `mypy` gate is currently advisory (non-blocking) while an existing type
  backlog is worked down — see [KNOWN_ISSUES.md](KNOWN_ISSUES.md). Do not
  introduce *new* mypy errors; fix any your change adds before committing.
- `pytest` must pass.

## Commit Convention

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short summary>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`. Keep
each commit focused on a single concern.

## Branch Naming

Branch from `main` using a `type/short-description` form, for example:

- `feat/responder-parser`
- `fix/canvas-layout-crash`
- `docs/readme-troubleshooting`

## Stability Policy: CLI and Parsers

The top-level CLI command surface and the set of bundled tool parsers are
considered **stable** for the current release line. To keep the tool
predictable for users and downstream scripts:

- Proposals to **add, remove, or restructure a top-level command** should start
  as a **discussion issue**, not a direct pull request.
- Proposals to **change existing parser behavior** (Nmap, CrackMapExec,
  Impacket, BloodHound, Responder, and the others) should likewise start as a
  discussion issue, so detection and output changes can be reviewed against the
  existing fixtures first.

New *parser plugins* that add support for additional real tools are welcome as
pull requests — see below.

## Parser Guidelines

- Inherit from `AbstractParser`.
- Implement `can_parse(content)` with a 0.0-1.0 score.
- Keep parsing recoverable where possible and return warnings in `ParsedResult`.
- Emit normalized `Finding` objects rather than pre-rendered Markdown.
- Include fixtures and parser tests.

## Writing A Parser Plugin

PentNote supports external parser plugins through Python entry points. Start with the full guide in [README.md#extending-pentnote](README.md#extending-pentnote) and the installable example in [examples/plugin_example/](examples/plugin_example/).

Plugin checklist:

- Subclass `AbstractParser`.
- Keep `tool_name` unique.
- Return `0.0` from `can_parse()` for unrelated output.
- Return `ParsedResult` from `parse()`.
- Never write files from parser code.
- Add tests for detection and parsed model output.

Plugins that add high-value real tools are welcome as pull requests to the main repository once they are stable and tested.

## Pull Requests

- Keep changes scoped.
- Add or update tests for behavior changes.
- Run the quality gate (above) before opening a PR.
