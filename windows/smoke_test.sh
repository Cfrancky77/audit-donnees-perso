#!/usr/bin/env bash
# Vérifications rapides de l'exécutable Windows (sans interface, sans scan réel). Git Bash sous Windows.
set -euo pipefail
cd "$(dirname "$0")/.."
exe="$(realpath "${1:-dist/audit-donnees-perso-windows-x86_64.exe}")"
home="$(mktemp -d)"
export USERPROFILE="$(cygpath -w "$home" 2>/dev/null || echo "$home")" HOME="$home" APPDATA="$home/AppData"
unset OSINT_DATA_DIR
trap 'kill "${pid:-0}" 2>/dev/null || true' EXIT

echo "== --help"
"$exe" --help

echo "== l'exécutable sait lancer du Python (--py -c / -m)"
"$exe" --py -c 'import sys; print("argv =", sys.argv); print("frozen =", getattr(sys, "frozen", False)); print("executable =", sys.executable)'
"$exe" --py -c 'import holehe.core, fastapi, uvicorn; print("imports ok")'
"$exe" --py -c '
import audit_donnees_perso as o
cmd = o.tool_cmd("maigret", "maigret")
print("maigret ->", cmd)
assert cmd and cmd[1] == "--py" and cmd[0] == o.sys.executable
print("self_cmd =", o.self_cmd())
'

echo "== outils"
"$exe" --py -m maigret --version
"$exe" --py -m sherlock_project --version

echo "== serveur (--serve, port 8300, 40 s max)"
"$exe" --serve &
pid=$!
for i in $(seq 1 80); do
  if curl -fsS http://127.0.0.1:8300/api/checklist >/dev/null 2>&1; then
    echo "serveur ok"
    curl -fsS http://127.0.0.1:8300/favicon.png | head -c 4 | grep -q PNG && echo "icône (favicon) ok"
    exit 0
  fi
  sleep 0.5
done
echo "le serveur n'a pas répondu" >&2
exit 1
