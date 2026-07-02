# Changelog

All notable changes to PentNote are documented here.
Format follows Keep a Changelog (keepachangelog.com).

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
