# Known Issues

This document tracks deferred work and known limitations in PentNote. It is
intentionally transparent: nothing here blocks normal use, but each item is
something a contributor could pick up.

## Static type checking (mypy) — non-blocking gate

**Status:** Deferred to a post-Beta cleanup.

The mypy gate is currently configured as **non-blocking** in `pyproject.toml`:

```toml
[tool.mypy]
ignore_errors = true
```

This means `mypy pentnote` reports success without enforcing type correctness.
The decision is deliberate for the Beta release — the code is **runtime-correct
(the full 429-test suite passes)**, but a meaningful backlog of static-typing
gaps remains. Rather than mass-suppress or hastily annotate (which risks
changing parser/model behavior), the gate stays advisory until the backlog is
worked down properly.

### Current backlog (with `ignore_errors = false`)

As measured with mypy 2.1.0: **122 errors across 39 files.**

By error code:

| Code | Count | Typical cause |
| ---- | ----- | ------------- |
| `misc` | 56 | "Too many positional arguments" — NamedTuple/dataclass call sites whose declared field types don't match positional usage |
| `attr-defined` | 21 | Attribute access on `object`-typed values |
| `arg-type` | 20 | Values typed as `object` flowing into constructors expecting `str`/`list[str]` |
| `assignment` | 12 | Container element-type widening, e.g. `list[DefenseRow]` vs `list[DefenseRow \| str]` |
| `call-overload`, `return-value`, `type-var`, `union-attr`, `operator`, `var-annotated`, `index` | 13 | Scattered — overload resolution and union narrowing |

Highest-error modules: `cli.py` (23), `graph/bloodhound.py` (9),
`parsers/c2/generic.py` (8), `sync/git.py` (8), `mitre/chain_detector.py` (7),
`parsers/v2/responder.py` (6).

### Re-enabling real type checking

When picking this up:

1. Set `ignore_errors = false` in `[tool.mypy]`.
2. Bump `python_version` to `3.12` **or** add an override for numpy — under
   `python_version = 3.11` mypy cannot parse numpy 2.x stubs (they use the
   PEP 695 `type` statement, which mypy only accepts for 3.12+):

   ```toml
   [[tool.mypy.overrides]]
   module = "numpy.*"
   follow_imports = "skip"
   ```

3. Work the backlog by error code (start with `misc`/`arg-type`, which share a
   common `object`-typing root), preferring real annotations over
   `# type: ignore`. Use targeted `# type: ignore[code]` only where a third
   party leaves no clean alternative.

## `known_ip` host-identity corroboration has no production caller

**Status:** Deferred backlog item, introduced with the v1.1.0 host-identity fix.

`resolve_host_note_path(notes_dir, target, *, known_ip=None)` auto-merges an
incoming write into an existing host note on either of two data-backed signals:
an IP-network identity match, or a hostname/alias match **corroborated** by a
caller-supplied `known_ip` equal to the note's recorded IP.

As of v1.1.0 **no production caller supplies `known_ip`** — all three callers
(`note`, the unsupported-tool recorder, and Ghost Log apply) pass the default
`None`, so only the IP-network-identity branch ever fires. The
corroborated-hostname branch is wired but unreached: in practice
**hostname-based identity resolution does not happen at all today**. A bare-name
write that can't be matched by IP always lands on a fresh note (plus a warning),
never merges. That is the intended safe tradeoff for now — "a duplicate beats a
silent wrong-merge" — but the corroboration path is effectively dead code until a
caller feeds it.

**Future work:** wire `known_ip` to a real, tool-observed signal — a DNS PTR/A
capture, a certipy/TLS certificate CN/SAN, or an explicit tool-reported
hostname→IP mapping — so the hostname-match branch becomes reachable and
name-based references can merge safely when corroborated. Until then the
hostname-match path stays inert by design.
