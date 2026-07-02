# PentNote

[![CI](https://github.com/A1GCH-afk/PentNote/actions/workflows/ci.yml/badge.svg)](https://github.com/A1GCH-afk/PentNote/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/pentnote)](https://pypi.org/project/pentnote/)
[![Python versions](https://img.shields.io/pypi/pyversions/pentnote)](https://pypi.org/project/pentnote/)
[![Downloads](https://img.shields.io/pypi/dm/pentnote)](https://pypi.org/project/pentnote/)
[![License: MIT](https://img.shields.io/github/license/A1GCH-afk/PentNote)](LICENSE)
[![ATT&CK Coverage](https://img.shields.io/badge/ATT%26CK-69%25-red.svg)](#mitre-attck-integration)

> Stop copy-pasting terminal output. PentNote turns pentest tool output into structured MITRE-tagged Obsidian notes with attack chains, risk scoring, remediation roadmaps, and Ghost Log automation.

> ⚠️ **Authorized Use Only** — PentNote is intended exclusively for authorized
> penetration tests, CTF competitions, and personal labs. Using this tool against
> systems without written permission is illegal. See [SECURITY.md](SECURITY.md).

## Overview

PentNote is a Python CLI for authorized security assessments. It converts raw
scanner, Active Directory, web, C2, and post-exploitation tool output into an
**engagement vault**: a folder of Obsidian Markdown notes, persistent workspace
state, MITRE ATT&CK context, D3FEND recommendations, reports, timelines,
Navigator layers, and BloodHound Canvas graphs. It's built for pentesters, red
teamers, and anyone documenting Hack The Box / Proving Grounds / CTF-style
engagements who wants structured notes instead of a pile of terminal scrollback.

PentNote's four core capabilities:

- **Automatic MITRE ATT&CK mapping** — findings are classified against ATT&CK
  techniques via rules, keywords, and port heuristics as they're parsed.
- **Attack chain detection** — recognizes complete attack chains (e.g. *Full AD
  Compromise*, *Kerberos Chain*, *Lateral Movement Chain*) from the TTPs
  observed so far.
- **Credential tracking** — a workspace of discovered credentials (hash,
  plaintext, Kerberos ticket, ...) with a Hashcat cracking workflow.
- **Report generation** — risk-scored, client-facing Markdown/HTML reports
  with a remediation roadmap and D3FEND countermeasures.

| Feature | PentNote | Manual Notes | Other Tools |
| --- | --- | --- | --- |
| Auto MITRE mapping | Yes | No | Partial |
| Attack chain detection | Yes | No | Rare |
| Ghost Log local shell-history extraction | Yes | No | No |
| Risk-scored reports | Yes | No | Partial |
| Remediation roadmap | Yes | Manual | Partial |
| Obsidian Canvas graphs | Yes | No | No |
| Hashcat workflow support | Yes | Manual | Partial |
| Built-in parsers | 25 | N/A | Varies |
| Open source | Yes | N/A | Varies |

> **📸 Demo media coming soon** — *A screenshot/GIF showing the parse → notes → report workflow will be added in the next release.*

### Supported Parsers

PentNote ships with 25 parser strategies:

| Category | Parsers |
| --- | --- |
| Network | Nmap |
| Active Directory | CrackMapExec/NetExec, Impacket secretsdump, BloodHound, Kerbrute, LDAPDomainDump, Rubeus, Certipy, Mimikatz, enum4linux-ng, Responder, PowerView, evil-winrm |
| Web | Gobuster, Feroxbuster, Nikto, Nuclei, sqlmap |
| Post-exploitation | WinPEAS, LinPEAS, Seatbelt, LaZagne |
| C2 | Sliver, Havoc |
| Fallback | Universal indicators: IPs, ports, hashes, CVEs, usernames, URLs |

Auto-detection picks the right parser from file content; use `--tool` to force
one explicitly:

```bash
pentnote status --parsers                       # list parsers and aliases
pentnote status --parsers-detect scan-output.txt # show auto-detection scores
pentnote parse scan.xml --tool nmap
pentnote parse cme.txt --tool cme
pentnote parse responder.log --tool responder
pentnote parse winpeas.txt --tool winpeas
pentnote parse linpeas.txt --tool linpeas
```

Parser architecture rule: parsers return a `ParsedResult`; they never write
files directly (see [Extending PentNote](#extending-pentnote)).

## Installation

PentNote requires **Python 3.11 or newer**.

```bash
pip install pentnote                 # core: CLI, parsers, MITRE, reports
pip install "pentnote[operator]"     # + Ghost Log, Ollama, screenshots/OCR,
                                      #   graph/Canvas export, Git sync, file watching
```

Development install:

```bash
git clone https://github.com/A1GCH-afk/PentNote.git
cd PentNote
python3 -m pip install -e ".[dev]"
pytest tests/ -v
```

Verify the install:

```bash
pentnote --version
pentnote status --parsers
```

## Quickstart

Create a vault, parse tool output, inspect ATT&CK context, and generate a report:

```bash
mkdir WingData && cd WingData
pentnote init WingData --scope 10.10.10.0/24 --output .
nmap -sV 10.10.10.10 -oX - | pentnote parse --tool nmap
pentnote mitre show
pentnote report --format html --with-defenses
```

Generated files land under:

- `.pentnote/` — engagement state (`config.json`, `local.json`, `findings.json`)
- `notes/` — generated Obsidian Markdown (hosts, findings, credentials, domain objects)
- `reports/` — reports and Navigator layer exports
- `raw/` — original tool output captured by `run`
- `attachments/` — screenshots and evidence (created on first `loot snap`)

`config.json` holds shared engagement metadata; `local.json` is operator-local
config (LHOST/LPORT, Ollama model, sync remote) and is Git-ignored. Always run
PentNote commands from inside the engagement folder, or point commands at a
vault explicitly with `--vault`/a vault-path argument where supported.

Common next commands:

```bash
pentnote status
pentnote log --timeline
pentnote sync --reindex
pentnote mitre chains
pentnote mitre next
```

## Command Reference

PentNote's CLI has 12 top-level commands. Several previously-standalone
commands are now flags on the command they're closest to in purpose:
`doctor` → `status --health`, `parsers` → `status --parsers`, `timeline` →
`log --timeline`, `index` → `sync --reindex`, `graph canvas` → `sync --graph`,
`snap` → `loot snap`.

| Command | Purpose |
| --- | --- |
| `init` | Initialize an engagement vault. |
| `run` | Run a pentest tool, save raw output, and auto-parse. |
| `parse` | Parse output you already have — a file, an externally-obtained scan, stdin (`cat scan.xml \| pentnote parse`), or a directory with `--recursive`. Use `run` instead to have PentNote execute the tool for you. |
| `status` | Show the engagement summary, parser info, or workspace health. |
| `targets` | Manage named target groups (scope subsets) inside an engagement. |
| `creds` | Credential workspace: add, list, export, crack tracking. |
| `loot` | Loot tracker (files, shells, flags, hashes, keys) and screenshots. |
| `mitre` | MITRE ATT&CK views: coverage, chains, next steps, Navigator export. |
| `log` | Attack log, plus Ghost Log automation and the timeline rebuild. |
| `note` | Manual per-host notes. |
| `report` | Generate a final Markdown/HTML report. |
| `sync` | Refresh the Obsidian index/Canvas and synchronize the vault with Git. |

> 📖 **Full command and per-tool usage guide:** every CLI command's flags,
> plus every supported tool with a live `run` example — see
> [USAGE.md](USAGE.md).

## Example Workflow

A full HTB/CTF-style run, start to finish:

```bash
mkdir MachineName && cd MachineName
pentnote init MachineName --scope 10.10.10.10 --output .

nmap -sV -sC --top-ports 1000 10.10.10.10 -oX scan.xml
pentnote parse scan.xml --tool nmap

pentnote log "Completed nmap service scan" --host 10.10.10.10
pentnote note add 10.10.10.10 "Initial web foothold suspected" --tag recon
pentnote loot add --type file --path scan.xml --host 10.10.10.10
pentnote loot snap 10.10.10.10

pentnote sync --reindex
pentnote log --timeline
pentnote mitre show
pentnote mitre chains
pentnote mitre coverage
pentnote mitre next
pentnote report --format both --with-defenses
pentnote mitre export --format navigator
```

Check the results:

```bash
cat notes/hosts/10-10-10-10.md
cat notes/LOOT.md
cat notes/01_Timeline.md
ls attachments/
ls reports/
```

`pentnote loot`, `pentnote creds`, and `pentnote log --timeline` are what keep
the engagement notebook coherent as a box evolves from recon to foothold to
domain admin.

## MITRE ATT&CK Integration

PentNote maps findings, open ports, parser-specific rules, and detected attack
chains to ATT&CK techniques as it parses tool output:

- **Classifier** (`pentnote/mitre/`) — rule-based + keyword + port→technique
  matching produces a technique ID, name, tactic, confidence, and source for
  each match.
- **Chain detector** — recognizes complete attack chains (e.g. *Full AD
  Compromise*, *Kerberos Chain*, *Lateral Movement Chain*) from the TTPs
  observed in an engagement.
- **D3FEND** — maps techniques to defensive countermeasures, included in
  reports via `--with-defenses`.
- **Coverage / Navigator** — tactic coverage analytics and ATT&CK Navigator
  layer export.

```bash
pentnote mitre show                        # all discovered TTPs
pentnote mitre chains                      # detected attack chains
pentnote mitre coverage                    # tactic coverage percentages
pentnote mitre coverage --tool             # built-in TTP coverage by source
pentnote mitre coverage --engagement       # only tactics with discovered TTPs
pentnote mitre next                        # suggested next steps
pentnote mitre next --show-secret          # include plaintext secrets in commands
pentnote mitre export --format navigator   # writes reports/layer.json
```

Current release coverage: 136 unique ATT&CK techniques, about 69% of the
bundled Enterprise dataset's total technique count.

> **📸 Demo media coming soon** — *A screenshot/GIF showing the MITRE ATT&CK Navigator layer will be added in the next release.*

## Reports

PentNote reports are designed to be client-facing:

- Executive summary
- Severity counts and affected assets
- Attack chains detected
- Top risks ordered by `RiskScore`
- Remediation roadmap with effort estimates
- Findings detail
- D3FEND recommendations
- Evidence appendix
- MITRE ATT&CK coverage

```bash
pentnote report --format markdown
pentnote report --format html --with-defenses
pentnote report --format both --with-defenses --redact
pentnote report --format html --with-defenses --compare-vault /path/to/previous-vault
```

`--redact` strips raw evidence from the generated report. `--compare-vault`
points at a previous engagement's vault so the report can call out findings
that have since been fixed.

> **📸 Demo media coming soon** — *A screenshot/GIF showing the generated HTML report will be added in the next release.*

## Git Sync & Vault Structure

An engagement vault looks like:

```text
<vault>/
├── .pentnote/
│   ├── config.json      # shared engagement config (name, scope, target groups)
│   ├── local.json       # operator-local secrets (lhost/lport, ollama_model) — git-ignored
│   └── findings.json    # deduplicated findings state
├── notes/
│   ├── hosts/  findings/  credentials/  domain/
│   ├── 00_Index.md       # generated by `sync --reindex`
│   ├── 01_Timeline.md    # generated by `log --timeline`
│   └── LOOT.md
├── reports/              # generated reports and the Navigator layer.json
├── raw/                  # raw tool output captured by `run`
└── attachments/          # screenshots and evidence
```

`sync` synchronizes the vault with Git and, by default, keeps the generated
index and Canvas graph fresh before it does:

```bash
pentnote sync --once                 # one pull/commit/push (also the bare-sync default)
pentnote sync --watch                # watch the vault and sync on changes
pentnote sync                        # same as --once, plus auto --reindex and auto --graph
pentnote sync --reindex              # rebuild notes/00_Index.md only, no Git sync
pentnote sync --graph \
  --bloodhound-json bloodhound.json \
  --canvas-output "Shortest Path to DA.canvas" \
  --layout radial --highlight-paths  # regenerate the Canvas only, no Git sync
```

A plain `pentnote sync` (no `--reindex`/`--graph` given) auto-refreshes both
the Obsidian index and — if a BloodHound export is available via
`--bloodhound-json` — the Canvas graph, then runs the Git sync, equivalent to
running `--reindex --graph` together. Passing `--reindex` and/or `--graph`
explicitly runs only the requested regeneration(s) and skips the Git sync
step entirely, so either works standalone in a vault with no Git remote
configured. `sync` requires `pentnote[operator]` (GitPython) for the Git
step; `--reindex` alone does not.

PentNote can turn BloodHound/SharpHound exports into Obsidian Canvas graphs
with deterministic layouts, node role colors, and missing-note warnings.
Layout modes: `auto`, `radial`, `tree`, `grid`, `force`. With
`--highlight-paths`, shortest paths render red, high-value attack edges
render orange, normal relationships render gray, and a legend node is added
to the Canvas. Open the resulting `.canvas` file in Obsidian to view linked
users, groups, computers, and attack-path edges — nodes are linked to the
generated Markdown notes under `notes/domain/`, `notes/hosts/`, and
`notes/credentials/`.

> **Demo media coming soon** — *A screenshot/GIF showing the Obsidian Canvas with a highlighted attack path will be added in the next release.*

Initialize Git in the vault if you haven't already:

```bash
git init
git remote add origin git@github.com:ORG/ENGAGEMENT-VAULT.git
```

PentNote keeps operator-local and sensitive files out of Git automatically
(`pentnote status --health` will flag and fix a missing entry):

```text
.pentnote/local.json
.pentnote/*.lock
.pentnote/*.pid
.pentnote/ghostlog-*.jsonl
.pentnote/cache/
```

## AI Assistant (Ollama / Ghost Log)

Ghost Log watches local shell history, filters interesting operator commands,
redacts secrets, asks a local Ollama model for strict structured extraction,
and applies extracted credentials, findings, and timeline entries to the
vault. **Ghost Log is local-only** — PentNote never sends shell history to a
remote API.

```bash
pip install "pentnote[operator]"
ollama pull llama3
pentnote log --daemon --model llama3   # run the shell-history daemon
pentnote log --status                  # current + cumulative session stats
pentnote log --stop
pentnote log --finding HASH_OR_TITLE   # Ghost Log entries linked to a finding
pentnote log --review                  # pending low-confidence review queue
```

Ghost Log tracks current-session and cumulative engagement counters, links
findings back to the source command that produced them, and gates low- or
very-low-confidence extractions into a review queue instead of writing them
straight to the vault. The Ollama endpoint defaults to `http://localhost:11434`.

## Extending PentNote

PentNote discovers parser plugins through Python entry points. Any package
that registers a class implementing `AbstractParser` is auto-loaded by
`pentnote.parsers.detector.available_parsers()`. Plugins are a good fit when
a parser is useful for your workflow but isn't ready to live in the main
PentNote repository yet.

Minimal parser example:

```python
# myparser/parser.py
from pentnote.core.deduplicator import finding_hash
from pentnote.core.models import Finding, MitreMatch, ParsedResult, Severity
from pentnote.parsers.base import AbstractParser


class MyToolParser(AbstractParser):
    tool_name = "mytool"
    aliases = ("mt", "my-tool")
    supported_extensions = (".txt", ".log")

    def can_parse(self, content: str) -> float:
        """Return a 0.0-1.0 confidence score."""
        signals = ["[MyTool]", "Scan complete"]
        hits = sum(1 for signal in signals if signal in content)
        return min(1.0, hits * 0.5)

    def parse(self, content: str) -> ParsedResult:
        findings = []
        for line in content.splitlines():
            if "VULN" not in line:
                continue
            title = f"Vulnerability: {line}"
            findings.append(
                Finding(
                    title=title,
                    severity=Severity.HIGH,
                    mitre_matches=[
                        MitreMatch(
                            technique_id="T1190",
                            technique_name="Exploit Public-Facing Application",
                            tactic="Initial Access",
                            confidence=0.8,
                            source="rule",
                        )
                    ],
                    affected_hosts=[],
                    evidence=line,
                    next_steps=["Verify and exploit in scope."],
                    defenses=[],
                    hash=finding_hash(self.tool_name, "", title),
                )
            )
        return ParsedResult(
            tool=self.tool_name,
            partial=False,
            hosts=[],
            credentials=[],
            findings=findings,
            domain_objects=[],
            raw_text=content,
        )
```

Register it in `pyproject.toml`:

```toml
[project.entry-points."pentnote.parsers"]
mytool = "myparser.parser:MyToolParser"
```

Test it:

```bash
pip install -e .
pentnote status --parsers | grep mytool
pentnote status --parsers-detect sample_output.txt
pentnote parse sample_output.txt --tool mytool
```

Parser requirements checklist:

- [ ] Subclasses `AbstractParser`
- [ ] `tool_name` is unique across all parsers
- [ ] `can_parse()` returns `0.0` for wrong tool output
- [ ] `parse()` never raises on partial or corrupt input
- [ ] `parse()` never writes files directly
- [ ] `ParsedResult.tool` matches `tool_name`
- [ ] New model needs go in `pentnote/core/models.py`
- [ ] Tests cover detection and parsed output boundaries

See `examples/plugin_example/` for a complete installable package that parses
fictional `MyScanner` output.

## Troubleshooting

`pentnote status --health` checks an engagement vault for common problems and
can repair the safe ones automatically:

- `local.json`/`workspace.json` missing from `.gitignore` (these can contain
  operator secrets and LHOST/LPORT values)
- `workspace.json` with overly permissive file permissions (should be `0o600`)
- corrupt `findings.json` or `workspace.json` (backed up with a timestamped
  suffix and reset to an empty, valid state)
- orphaned finding notes with no matching entry in `findings.json`
- duplicate MITRE technique IDs in the bundled `rules.json`

```bash
pentnote status --health                     # report issues only
pentnote status --health --fix               # repair high/medium/critical issues
pentnote status --health --fix --dry-run     # preview without changing files
pentnote status --health --fix --include-low # also clean up low-severity issues (e.g. orphaned notes)
```

If a parser doesn't recognize your input, force it explicitly rather than
relying on auto-detection:

```bash
pentnote parse output.txt --tool cme
```

Use `--` and long option names (`--tool`, not `-tool` or `-t`) — PentNote's
options are not abbreviated. For Nmap, prefer XML output piped directly into
`parse` for the most complete extraction:

```bash
nmap -sV -sC -p- 10.10.10.10 -oX - | pentnote parse --tool nmap
```

## Contributing, License, Security

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a pull request. External parser plugins are especially
welcome; see [Extending PentNote](#extending-pentnote) above.

PentNote is released under the [MIT License](LICENSE).

For the authorized-use policy and how to report a vulnerability privately,
see [SECURITY.md](SECURITY.md).
