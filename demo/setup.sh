#!/usr/bin/env bash
set -euo pipefail

echo "Creating PentNote demo vault..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES="$REPO_ROOT/tests/fixtures"

rm -rf demo-vault
mkdir -p demo-vault
cd demo-vault

pentnote init DemoEngagement \
  --scope 192.168.56.0/24 \
  --scope north.sevenkingdoms.local \
  --output .

pentnote targets add AD \
  --scope 192.168.56.0/24 \
  --scope north.sevenkingdoms.local

pentnote parse "$FIXTURES/nmap_sample.xml" --tool nmap
pentnote parse "$FIXTURES/cme_sample.txt" --tool cme
pentnote parse "$FIXTURES/impacket_sample.txt" --tool impacket-secretsdump
pentnote parse "$FIXTURES/bloodhound_sample.json" --tool bloodhound
pentnote parse "$FIXTURES/gobuster_sample.txt" --tool gobuster
pentnote parse "$FIXTURES/responder_sample.log" --tool responder
pentnote parse "$FIXTURES/winpeas_sample.txt" --tool winpeas

pentnote creds add brandon.stark \
  --secret 'iseedeadpeople' \
  --type plaintext \
  --host 192.168.56.11 \
  --tag demo

pentnote loot add --type flag \
  --value 'HTB{demo_user_flag}' \
  --host 192.168.56.11 \
  --notes "Demo user flag"

pentnote log "Demo: completed nmap scan" \
  --host 192.168.56.11

pentnote sync --reindex
pentnote log --timeline
pentnote mitre export --format navigator
pentnote report --format both --with-defenses

echo "Demo vault created at demo-vault/"
echo "Open demo-vault/ in Obsidian to explore"
echo "View report: demo-vault/reports/pentnote-report.html"
