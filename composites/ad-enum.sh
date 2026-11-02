#!/usr/bin/env bash
# composite: ad-enum — unauthenticated AD enumeration bundle in ONE turn.
# usage: ad-enum.sh <dc-ip> [domain.fqdn]
set -u
IP="${1:?usage: ad-enum.sh <dc-ip> [domain.fqdn]}"
DOM="${2:-}"

section() { printf '\n=== %s ===\n' "$1"; }

section "target"
echo "$IP ${DOM}"

section "smb"
if command -v netexec >/dev/null; then
  timeout 90 netexec smb "$IP" 2>&1 | head -15
  timeout 90 netexec smb "$IP" --shares -u '' -p '' 2>&1 | head -25
else
  echo "skipped: netexec not installed"
fi

section "ldap-rootdse"
if command -v ldapsearch >/dev/null; then
  timeout 60 ldapsearch -x -H "ldap://$IP" -s base namingContexts \
    supportedCapabilities 2>&1 | head -25
else
  echo "skipped: ldapsearch not installed"
fi

section "dns"
if command -v dig >/dev/null; then
  [ -n "$DOM" ] && timeout 30 dig +short "@$IP" "$DOM" A 2>&1 | head -10
  [ -n "$DOM" ] && timeout 30 dig +short "@$IP" "$DOM" AXFR 2>&1 | head -30
  timeout 30 dig +short "@$IP" -t SRV _ldap._tcp."${DOM:-}" 2>&1 | head -10
else
  echo "skipped: dig not installed"
fi

section "kerberos"
timeout 90 nmap -Pn -p 88 -sV --open "$IP" 2>&1 | grep -E "^(88|PORT|Service|Nmap scan)" | head -10

section "done"
