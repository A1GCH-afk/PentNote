# Changelog

All notable changes to PentNote are documented here.
Format follows Keep a Changelog (keepachangelog.com).

## [1.1.0] - 2026-07-13

### Added
- `pentnote status --health --check-merges` — a read-only audit that flags name
  collisions between *separate* host notes: two notes that share a host/NetBIOS
  name but sit at different IPs with no confirmed network-layer link. It lists
  each affected note and the note it collides with so you can review and split
  them by hand; it never edits or splits a note automatically.

  Scope and limitation: this catches only cases where both hosts still have
  their own separate notes. It does **not** recover a host that was already
  fully merged/absorbed into another note under the old rule — once two hosts'
  data has been combined into a single note, there is no remaining trace on disk
  to detect that it happened. If you suspect a specific host was wrongly merged
  in a v1.0.1 vault, that needs a manual review of the note's contents, not this
  check.

### Changed
- **Host identity merging now requires a confirmed, data-backed link.** v1.0.1
  resolved host notes referenced by IP/hostname/FQDN to one canonical note "when
  the note already has a confirmed link" — but it accepted a matching
  hostname/NetBIOS name (the text alone) as that link. It no longer does: a write
  is folded into an existing host note only on network-layer evidence — a matching
  IP, or a hostname backed by a matching IP — never on the name text alone. Two
  different hosts that happen to share a name (a domain-controller pair, cloned
  images, reused default names) no longer silently collapse into one note; the
  ambiguous write goes to a separate note with a warning instead. **This does not
  rewrite notes you already have:** vaults created with v1.0.1 may still contain
  notes that were merged under the old name-only rule, so run
  `status --health --check-merges` to find and review any that were affected.
- Internal code-quality pass with no behavior change: added missing type hints
  and docstrings, removed unreferenced dead helpers, and consolidated a
  duplicated graph-layout helper.
- No change to the CrackMapExec/NetExec parser this release — the artifact-path
  loot recovery and unrecognized-output surfacing already shipped in v1.0.1.

## [1.0.1] - 2026-07-10

### Added
- `loot remove <id>` / `loot remove --last` to undo a bad `loot add`.
- `--host`/`--type`/`--user` filters on `loot summary`, matching the filters
  `loot list` and `loot add` already supported.
- A host note `## Unparsed / Unsupported Tools` section recording tool runs
  that have no dedicated parser, so they leave a trace instead of vanishing.
- `net user`/`net group` output now populates AD domain-object notes (account
  info, group memberships) instead of only surfacing as finding evidence.

### Changed
- Interactive-shell raw captures (evil-winrm) strip ANSI redraw/cursor noise
  before saving; other tools' captures remain byte-identical.
- Raw `.txt` captures now record their invoking command as a header line.
- Host notes now merge additively across tool re-runs instead of the most
  recent tool's write silently discarding fields (hostname, AV products) an
  earlier tool had already recorded.
- Host notes referenced by different identifiers (IP, hostname, FQDN, in any
  case) now resolve to one canonical note instead of fragmenting into
  duplicates, when the note already has a confirmed link to that identifier.
- The Markdown report now uses one consistent empty-section marker instead of
  several different ones across sections.

### Fixed
- `nxc`/`crackmapexec` `saved to: <path>` lines (`--generate-krb5-file`
  and the analogous SAM/LSA/NTDS dump paths) were silently discarded instead
  of being recorded as loot.
- Parser detection errors were silently scored 0, indistinguishable from a
  parser that simply didn't match; they now surface a warning.
- Every PentNote-managed state file (workspace/engagement/ghostlog JSON
  stores, `local.json`, host and credential notes, the collaboration-mode
  `.gitignore`, and raw tool-output captures) is now written atomically
  (temp-file + fsync + rename) instead of via a direct overwrite, so a crash,
  kill, disk-full, or Ctrl-C mid-write can no longer leave it truncated or
  corrupted.

## [1.0.0] - 2026-07-02

### Added
- `SECURITY.md` with an authorized-use policy and vulnerability reporting guidance.
- `KNOWN_ISSUES.md` documenting known limitations and deferred work.
- A default 60-second timeout on test runs so the suite cannot hang.
- Optional `numpy`-backed layout for the BloodHound Canvas export.

### Changed
- Marked the project **Beta** and expanded the packaging metadata: project URLs, README badges, and clone instructions.
- Consolidated the CLI to 12 focused top-level commands. Several former commands are now flags or subcommands of a closely related command:
  - `doctor` → `status --health` (with `--fix`, `--dry-run`, `--include-low`)
  - `parsers list` / `parsers detect` → `status --parsers` / `status --parsers-detect FILE`
  - `timeline` → `log --timeline`
  - `index` → `sync --reindex`
  - `graph canvas` → `sync --graph` (with `--bloodhound-json`, `--canvas-output`, `--layout`, `--highlight-paths`)
  - `snap` → `loot snap`
- `sync` with no flags now refreshes the Obsidian index (and the BloodHound Canvas, when an export is configured) before running the Git sync. Passing `--reindex` and/or `--graph` performs only that regeneration and skips Git, so both work in a vault with no Git remote.
- The BloodHound Canvas layout falls back to a radial layout when `numpy` is not installed, instead of failing.
- Consolidated all project documentation into a single comprehensive `README.md` covering installation through troubleshooting.

### Fixed
- A missing client-side timeout on local Ollama calls that could hang the Ghost Log assistant.
- A packaging error that could break installation from the built wheel.

### Removed
- Several legacy and internal-only modules, plus superseded internal planning documents.
- The `payloads`, `compare`, and `migrate` commands. The living-off-the-land guidance that backed `payloads` is retained internally but is no longer a separate command.
- The standalone `docs/` directory; its content now lives in `README.md`.

> Note: versions 1.0.0–1.5.0 below were internal pre-release development
> iterations, not public releases. This is PentNote's first public release,
> versioned 1.0.0 above.

## [1.5.0] - 2026-05-03
### Added
- WinPEAS and LinPEAS parsers
- Remediation roadmap in reports
- Ghost Log cumulative session history
- Canvas attack-path highlighting (`--highlight-paths`)
- Hashcat mode-aware cracking guidance
- `pentnote creds crack-status` command
- AV product detection from CME `--enum-av` output
- `pentnote report --compare-vault` flag

## [1.4.0] - 2026-04-30
### Added
- Responder parser (Net-NTLMv1/Net-NTLMv2)
- AV/EDR-aware payload LOTL suggestions
- Ghost Log finding-to-command correlation
- Enhanced engagement compare (severity trend, MITRE diff)
- Extended credential secret types (sha256, net-ntlmv2...)
- C2 session findings with ATT&CK TTPs

## [1.3.0] - 2026-04-27
### Added
- `pentnote doctor --fix` with `--dry-run` and `--include-low`
- Canvas layout modes (radial, tree, grid, force)
- Canvas node role colors
- Risk scoring (`RiskScore` model)
- ATT&CK coverage expansion to 96 TTPs
- Ghost Log session tracking and `--status`

## [1.2.0] - 2026-04-25
### Added
- Ghost Log daemon with local Ollama extraction
- BloodHound Canvas generation
- Hashcat potfile sync
- `pentnote compare` command
- Executive summary in reports
- Git sync support

## [1.1.0] - 2026-04-22
### Added
- MITRE ATT&CK classification and coverage
- D3FEND countermeasure mapping
- Attack chain detection
- Workspace: credentials, notes, loot, logs
- Navigator layer export
- Evidence/screenshot support
- Payload LOTL guidance

## [1.0.0] - 2026-04-20
### Added
- Initial release
- Nmap, CME, Impacket parsers
- Basic Obsidian Markdown notes
- MITRE tagging
