# PentNote Usage Guide

The complete usage reference for PentNote: every CLI command's flags in
**PentNote Commands** below, then every one of the 25 built-in tool parsers
in the tool-by-tool reference that follows it. For every tool, `run` is
the recommended path — it executes the tool live, saves the raw output, and
auto-parses it in one step. `parse` is the fallback for output you already
have on disk (an externally-obtained scan, a teammate's export, or a batch
of files). See README's [Overview](README.md#overview) and
[Quickstart](README.md#quickstart) for the onboarding narrative — this guide
is pure reference. README's [Command Reference](README.md#command-reference)
keeps the one-line command table; the full flag-by-flag detail lives here.

All examples use HTB/lab-style placeholders (`10.10.10.10`, `LAB\alice`,
`Pass123!`) — never real targets or credentials.

## PentNote Commands

### `init`

Initialize an engagement vault.

```bash
pentnote init ENGAGEMENT_NAME --scope 10.10.10.0/24 --output .
pentnote init --wizard   # interactive prompts for name/type/scope/client
```

Flags: `--scope` (CIDR or scope descriptor), `--output` (vault path,
default `.`), `--wizard` (interactive prompts instead of flags).

### `run`

Execute a tool live, save its raw output, and auto-parse it.

```bash
pentnote run nmap -sV 10.10.10.10                        # saves raw + auto-parses
pentnote run crackmapexec smb 10.10.10.0/24 --no-parse    # raw only
```

Flags: `--tool` (override the parser), `--no-parse` (save raw output only,
skip parsing), `--no-universal` (skip parsing if no specific parser is
configured for the tool, instead of falling back to the universal parser),
`-q`/`--quiet` (suppress the wrapped tool's own output).

See the tool-by-tool reference below for `run` examples against each of
the 25 supported tools.

### `parse`

Parse existing tool output you already have — a file, stdin, or a
`--recursive` directory — without re-running the tool.

```bash
pentnote parse scan.xml --tool nmap
pentnote parse scans/ --recursive --output vault
cat secretsdump.txt | pentnote parse --tool impacket-secretsdump
```

Flags: `--tool` (force a parser by tool name), `--output` (output vault/notes
directory), `--recursive` (process a directory of files), `--ai-summary`
(reserved for local AI summaries; requires `pentnote[operator]`).

### `status`

Show the engagement summary, parser info, or workspace health.

```bash
pentnote status                                    # engagement summary
pentnote status --health                           # workspace health check
pentnote status --health --fix                     # repair safe defaults
pentnote status --health --fix --dry-run           # preview fixes
pentnote status --health --fix --include-low       # also clean up orphans
pentnote status --parsers                          # list parsers
pentnote status --parsers-detect FILE              # auto-detection scores
```

Takes an optional `VAULT_PATH` positional argument to target an engagement
other than the current directory (e.g. `pentnote status ../other-engagement`).
Flags: `--health` (check workspace health instead of the summary), `--fix`
(with `--health`, repair missing safe defaults), `--dry-run` (with
`--health --fix`, preview without changing files), `--include-low` (with
`--health --fix`, also apply low-severity cleanup fixes), `--parsers` (list
available parsers and their aliases/extensions), `--parsers-detect FILE`
(show auto-detection scores for FILE).

See [Troubleshooting](README.md#troubleshooting) for what `--health` checks.

### `targets`

Manage named target groups (scope subsets) inside an engagement.

```bash
pentnote targets add "DC01" --scope 10.10.10.10 --description "Domain controller"
pentnote targets list
pentnote targets show "DC01"
```

`add` requires `--scope` and takes an optional `--description`; `list` and
`show` take no target-specific flags. All three accept `--vault PATH` to
target an engagement other than the current directory.

### `creds`

Credential workspace: add, list, export, crack tracking.

```bash
pentnote creds add alice --secret 'Pass123!' --type plaintext --host 10.10.10.10
pentnote creds list --type ntlm
pentnote creds export --format hashcat --output ntlm.txt
pentnote creds export --format wordlist
pentnote creds update Administrator --cracked "P@ssw0rd123"
pentnote creds tag Administrator domain-admin
pentnote creds note Administrator "used for lateral movement"
pentnote creds crack-status
pentnote creds sync-pot ~/.hashcat/hashcat.potfile
```

`add` requires `--secret`, `--type`, `--host` (plus optional `--domain`,
`--tag`, `--notes`). `list` filters on `--type`, `--cracked`/`--uncracked`,
`--host`, `--domain`, `--user`, `--tag`, `--tool`, and reveals secrets with
`--show-secret`. Export formats: `hashcat`, `john`, `wordlist`, `spray`,
`csv`.

### `loot`

Loot tracker (files, shells, flags, hashes, keys) and screenshots.

```bash
pentnote loot add --type file --path /etc/passwd --host 10.10.10.10
pentnote loot add --type shell --host 10.10.10.10 --user www-data --method RCE
pentnote loot add --type flag --value "HTB{user_flag}" --host 10.10.10.10
pentnote loot add --type hash --value <ntlm-hash> --user Administrator --host 10.10.10.10
pentnote loot list
pentnote loot summary
pentnote loot snap 10.10.10.10          # requires pentnote[operator]
```

Loot types: `file`, `flag`, `shell`, `hash`, `secret`, `key`. `add` requires
`--type` and `--host`; `--path`/`--value`/`--user`/`--method`/`--notes` are
used depending on type. Loot is written to `notes/LOOT.md`. `snap` captures
the current screen and links it into the target's host note under
`attachments/`; with `pytesseract` and the system Tesseract binary
installed, the screenshot also gets hidden OCR text so it's searchable in
Obsidian. `snap` also accepts `--vault PATH` to target an engagement other
than the current directory.

### `mitre`

MITRE ATT&CK views for the active engagement.

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

See [MITRE ATT&CK Integration](README.md#mitre-attck-integration) for what
each view means.

### `report`

Generate a final Markdown/HTML report.

```bash
pentnote report --format markdown
pentnote report --format html --with-defenses
pentnote report --format both --with-defenses --redact
pentnote report --format html --with-defenses --compare-vault /path/to/previous-vault
```

`--format` is `markdown`, `html`, or `both` (default `markdown`).
`--with-defenses` includes D3FEND mappings. `--redact` strips raw evidence
from the generated report. `--compare-vault` points at a previous
engagement's vault so the report can call out findings that have since been
fixed. `--vault` (distinct from `--compare-vault`) targets an engagement
other than the current directory for the report itself. See
[Reports](README.md#reports) for what a report contains.

### `log`

Attack log, plus Ghost Log automation and the timeline rebuild.

```bash
pentnote log "Completed nmap service scan" --host 10.10.10.10 --tag recon
pentnote log list --today
pentnote log --daemon --model llama3   # run the shell-history daemon
pentnote log --status                  # current + cumulative session stats
pentnote log --start
pentnote log --stop
pentnote log --finding HASH_OR_TITLE   # Ghost Log entries linked to a finding
pentnote log --review                  # pending low-confidence review queue
pentnote log --timeline                # rebuild notes/01_Timeline.md
```

`log list` filters on `--host`, `--tag`, `--today`. Ghost Log's flags
(`--daemon`, `--start`, `--stop`, `--status`, `--model`, `--quiet`,
`--finding`, `--review`, and `--history PATH` to override the shell
history file the daemon watches — defaults to `$HISTFILE` or
`~/.bash_history`/`~/.zsh_history`) and `--timeline` (plus `--vault`, used
with `--timeline`) are covered in
[AI Assistant](README.md#ai-assistant-ollama--ghost-log) and
[Git Sync & Vault Structure](README.md#git-sync--vault-structure).

### `note`

Manual per-host notes.

```bash
pentnote note add 10.10.10.10 "Admin portal exposed" --tag recon
pentnote note list --host 10.10.10.10
pentnote note delete 1
```

`add` takes a target (host or finding) and text, plus an optional `--tag`.
`list` and `delete` both filter on `--host`, `--tag`, `--finding` —
`delete NUMBER` deletes the Nth note from that same filtered view, so pair
it with whichever filters produced that number in `list`.

### `sync`

Refresh the Obsidian index/Canvas and synchronize the vault with Git.

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

`--reindex` and `--graph` each run standalone (no Git sync), so both work in
a vault with no Git remote; a plain `sync` runs both regenerations and then
the Git sync. `--graph` requires `--bloodhound-json`; `--canvas-output`
(default `Shortest Path to DA.canvas`), `--layout` (`auto`, `radial`,
`grid`, `tree`, `force` — default `auto`), and `--highlight-paths` all
apply to it. `--vault` targets an engagement other than the current
directory. See
[Git Sync & Vault Structure](README.md#git-sync--vault-structure) for the
full vault layout and layout-mode details.

## Network

### Nmap

**Detects:** Open ports, service versions, OS fingerprints.

**Live run (recommended):**
```bash
pentnote run nmap -sV -sC --top-ports 1000 10.10.10.10
```

**Already have output on disk:**
```bash
pentnote parse scan.xml --tool nmap
```

**Notes:** Prefer `-oX -` piped into `parse` for the most complete
extraction if not using `run` directly.

## Active Directory

### CrackMapExec / NetExec

**Detects:** SMB shares, logged-in sessions, credential validation results
across a target range.

**Live run (recommended):**
```bash
pentnote run crackmapexec smb 10.10.10.0/24 -u alice -p 'Pass123!'
```

**Already have output on disk:**
```bash
pentnote parse cme.txt --tool cme
```

**Notes:** The upstream project ships both `netexec`/`nxc` and the legacy
`crackmapexec` binary names — all three, plus `cme`, resolve to the same
parser.

### Impacket secretsdump

**Detects:** SAM/LSA/NTDS secrets and hashes dumped from a remote host.

**Live run (recommended):**
```bash
pentnote run impacket-secretsdump 'LAB/alice:Pass123!@10.10.10.10'
```

**Already have output on disk:**
```bash
pentnote parse secretsdump.txt --tool impacket-secretsdump
```

**Notes:** Target syntax is `[[domain/]username[:password]@]<host>`; add
`-hashes LM:NT` instead of a password for pass-the-hash.

### BloodHound

**Detects:** Domain objects (users, groups, computers) and attack-path
edges for the Canvas graph.

**Live run (recommended):**
```bash
pentnote run bloodhound-python -u alice -p 'Pass123!' -d lab.local -ns 10.10.10.10 -c All --zip
```

**Already have output on disk:**
```bash
pentnote parse bloodhound.json --tool bloodhound
```

**Notes:** `bloodhound-python`/SharpHound write their collection to
JSON/ZIP files, not stdout, so `run` here only saves the console log. This
parser (and `parse --tool bloodhound`) expects a simplified
`{"nodes": [...], "edges": [...]}` graph document, not the native
SharpHound export — for a real SharpHound/bloodhound-python collection
(file or folder), use `pentnote sync --graph --bloodhound-json <path>`
instead, which understands the native format directly (see
[Git Sync & Vault Structure](README.md#git-sync--vault-structure)).

### Kerbrute

**Detects:** Valid AD usernames and valid credential logins discovered via
Kerberos pre-auth.

**Live run (recommended):**
```bash
pentnote run kerbrute userenum -d lab.local --dc 10.10.10.10 usernames.txt
```

**Already have output on disk:**
```bash
pentnote parse kerbrute.txt --tool kerbrute
```

**Notes:** `passwordspray -d lab.local --dc 10.10.10.10 usernames.txt 'Pass123!'`
is the companion subcommand for valid-login (rather than valid-username)
results.

### LDAPDomainDump

**Detects:** Domain users, groups, and computers enumerated over LDAP.

**Live run (recommended):**
```bash
pentnote run ldapdomaindump -u 'LAB\alice' -p 'Pass123!' 10.10.10.10
```

**Already have output on disk:**
```bash
pentnote parse domain_dump.json --tool ldapdomaindump
```

**Notes:** The real tool writes `domain_users.json`/`domain_groups.json`/
`domain_computers.json` (plus HTML/greppable output) to disk, not stdout —
`run` only saves its console log. This parser expects those merged into a
single simplified `{"users": [...], "groups": [...], "computers": [...]}`
document.

### Rubeus

**Detects:** Kerberoast/AS-REP-roast hashes and other Kerberos ticket
material.

**Live run (recommended):**
```bash
pentnote run Rubeus.exe kerberoast --tool rubeus
```

**Already have output on disk:**
```bash
pentnote parse rubeus.txt --tool rubeus
```

**Notes:** Windows-only; there's no `run` entry for it yet, so `--tool` is
required to attach the right parser instead of the universal fallback.
Typically captured from an active session (evil-winrm, a C2 beacon) rather
than run directly from the PentNote host — paste the console output to a
file and `parse` it.

### Certipy

**Detects:** AD CS certificate templates, CAs, and ESC-style
misconfigurations.

**Live run (recommended):**
```bash
pentnote run certipy find -u alice@lab.local -p 'Pass123!' -dc-ip 10.10.10.10 -vulnerable --tool certipy
```

**Already have output on disk:**
```bash
pentnote parse certipy_find.txt --tool certipy
```

**Notes:** `certipy` isn't in PentNote's built-in raw-run tool table yet,
so `--tool certipy` is required to attach the parser instead of the
universal fallback.

### Mimikatz

**Detects:** Plaintext/NTLM/Kerberos credentials extracted from LSASS
memory.

**Live run (recommended):**
```bash
pentnote run mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit --tool mimikatz
```

**Already have output on disk:**
```bash
pentnote parse mimikatz.txt --tool mimikatz
```

**Notes:** Windows-only and typically operated interactively; `--tool` is
required since it has no built-in raw-run entry. Capture the console
output (or use [Ghost Log](README.md#ai-assistant-ollama--ghost-log) on a
live session) and `parse` the transcript.

### enum4linux-ng

**Detects:** SMB/domain enumeration data (users, shares, groups,
policies).

**Live run (recommended):**
```bash
pentnote run enum4linux-ng -A 10.10.10.10
```

**Already have output on disk:**
```bash
pentnote parse enum4linux.txt --tool enum4linux
```

**Notes:** Invoke it as `enum4linux-ng` (no `.py`) so PentNote's tool
table matches it; `-A` runs the full simple-enumeration suite.

### Responder

**Detects:** Captured Net-NTLMv1/v2 hashes from LLMNR/NBT-NS/mDNS
poisoning.

**Live run (recommended):**
```bash
pentnote run responder -I eth0 -v
```

**Already have output on disk:**
```bash
pentnote parse responder.log --tool responder
```

**Notes:** Requires an interface with poisoning traffic in scope —
authorized engagement only. Runs until interrupted; the raw log is saved
and parsed on exit.

### PowerView

**Detects:** AD objects enumerated via PowerView/SharpView-style cmdlets
(users, groups, ACLs).

**Live run (recommended):**
```bash
pentnote run powerview "Get-NetUser | select samaccountname,description"
```

**Already have output on disk:**
```bash
pentnote parse powerview.txt --tool powerview
```

**Notes:** PowerView is a set of PowerShell cmdlets loaded via
`Import-Module PowerView.ps1` inside an active session, not a standalone
Linux CLI — in practice the operator copies the session's console output
to a file and runs `parse` on it.

### evil-winrm

**Detects:** Commands and output captured from an Evil-WinRM shell
session.

**Live run (recommended):**
```bash
pentnote run evil-winrm -i 10.10.10.10 -u alice -p 'Pass123!'
```

**Already have output on disk:**
```bash
pentnote parse evilwinrm.txt --tool evil-winrm
```

**Notes:** It's an interactive shell — `run` captures whatever the session
prints before it exits. Pass evil-winrm's own `-l`/`--log` flag to save a
full transcript to disk, then `parse` that file for a complete extraction.

## Web

### Gobuster

**Detects:** Discovered directories/files and their HTTP status codes from
brute-force enumeration.

**Live run (recommended):**
```bash
pentnote run gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt
```

**Already have output on disk:**
```bash
pentnote parse gobuster.txt --tool gobuster
```

### Feroxbuster

**Detects:** Discovered paths and HTTP status codes from recursive content
discovery.

**Live run (recommended):**
```bash
pentnote run feroxbuster -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt
```

**Already have output on disk:**
```bash
pentnote parse feroxbuster.txt --tool feroxbuster
```

### Nikto

**Detects:** Known-vulnerable web server signatures, outdated software,
and misconfigured endpoints.

**Live run (recommended):**
```bash
pentnote run nikto -host 10.10.10.10
```

**Already have output on disk:**
```bash
pentnote parse nikto.txt --tool nikto
```

**Notes:** Nikto's target flag is `-host` (aliased `-url`); there's no
bare `-h` for the target.

### Nuclei

**Detects:** Template-based vulnerability findings with severity and
CVE/template IDs.

**Live run (recommended):**
```bash
pentnote run nuclei -u http://10.10.10.10 -t cves/ -severity high,critical
```

**Already have output on disk:**
```bash
pentnote parse nuclei.txt --tool nuclei
```

### sqlmap

**Detects:** SQL injection points and the parameters they affect.

**Live run (recommended):**
```bash
pentnote run sqlmap -u "http://10.10.10.10/item.php?id=1" --batch
```

**Already have output on disk:**
```bash
pentnote parse sqlmap.txt --tool sqlmap
```

## Post-exploitation

### WinPEAS

**Detects:** Windows privilege-escalation vectors (misconfigurations,
weak permissions, cached credentials).

**Live run (recommended):**
```bash
pentnote run winPEASx64.exe
```

**Already have output on disk:**
```bash
pentnote parse winpeas.txt --tool winpeas
```

### LinPEAS

**Detects:** Linux privilege-escalation vectors (SUID binaries,
sudo misconfigurations, cached credentials).

**Live run (recommended):**
```bash
pentnote run linpeas.sh
```

**Already have output on disk:**
```bash
pentnote parse linpeas.txt --tool linpeas
```

### Seatbelt

**Detects:** Windows host security configuration and misconfigurations.

**Live run (recommended):**
```bash
pentnote run Seatbelt.exe -group=all
```

**Already have output on disk:**
```bash
pentnote parse seatbelt.txt --tool seatbelt
```

### LaZagne

**Detects:** Recovered local application credentials.

**Live run (recommended):**
```bash
pentnote run lazagne.exe all
```

**Already have output on disk:**
```bash
pentnote parse lazagne.txt --tool lazagne
```

## C2

### Sliver

**Detects:** C2 sessions/beacons, downloaded loot, and credentials
observed in the Sliver console log.

**Live run (recommended):**
```bash
pentnote run sliver-client --tool sliver
```

**Already have output on disk:**
```bash
pentnote parse sliver_session.log --tool sliver
```

**Notes:** Sliver's client is an interactive console, not a one-shot scan
— `sliver` has no built-in raw-run entry, so `--tool sliver` is required.
Capture a session transcript (`script sliver_session.log`, or
[Ghost Log](README.md#ai-assistant-ollama--ghost-log) on the live
session) and `parse` it.

### Havoc

**Detects:** C2 sessions/Demons, downloaded loot, and credentials observed
in the Havoc console log.

**Live run (recommended):**
```bash
pentnote run havoc client --tool havoc
```

**Already have output on disk:**
```bash
pentnote parse havoc_session.log --tool havoc
```

**Notes:** Same as Sliver — an interactive console with no built-in
raw-run entry, so `--tool havoc` is required. Capture and `parse` a
session transcript.

## Fallback

### Universal indicators

No dedicated live-run example — this is the fallback parser PentNote uses
automatically when no dedicated parser matches (see
[Supported Parsers](README.md#supported-parsers) for the detection order).
It extracts common indicators — IPs, ports, hashes, CVEs, usernames,
URLs — from arbitrary tool output via `pentnote parse <file>` or
`pentnote parse <file> --tool universal`, so an unconfigured tool's raw
output still yields some structured data rather than nothing.
