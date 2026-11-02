#!/usr/bin/env bash
# composite: web-recon — standard first-pass web chain in ONE turn.
# usage: web-recon.sh <base-url> [wordlist]
# Run under evidence capture: python3 scripts/capture-command.py -- composites/web-recon.sh <url>
set -u
URL="${1:?usage: web-recon.sh <base-url> [wordlist]}"
WL="${2:-/usr/share/wordlists/dirb/common.txt}"
T=90

section() { printf '\n=== %s ===\n' "$1"; }

section "target"
echo "$URL"

section "headers"
curl -sS -k -m "$T" -I "$URL" 2>&1 | head -40

section "tech-fingerprint"
command -v whatweb >/dev/null && timeout "$T" whatweb -a 1 "$URL" 2>&1 | head -10 \
  || echo "skipped: whatweb not installed"

section "robots-sitemap"
for path in robots.txt sitemap.xml; do
  code=$(curl -sS -k -m 20 -o /dev/null -w '%{http_code}' "$URL/$path" 2>/dev/null)
  echo "$path -> $code"
done
curl -sS -k -m 20 "$URL/robots.txt" 2>/dev/null | head -20

section "dir-scan (shallow)"
if command -v feroxbuster >/dev/null && [ -r "$WL" ]; then
  timeout 240 feroxbuster -u "$URL" -w "$WL" -d 2 -t 3 -q --silent \
    --extract-links 2>/dev/null | head -60
else
  echo "skipped: feroxbuster or wordlist missing ($WL)"
fi

section "done"
