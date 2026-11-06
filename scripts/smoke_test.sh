#!/usr/bin/env bash
# Vérifications rapides d'une AppImage construite (sans interface, sans scan réel).
set -euo pipefail
cd "$(dirname "$0")/.."
img="$(realpath "${1:-audit-donnees-perso-x86_64.AppImage}")"
export HOME="$(mktemp -d)"   # ne touche pas au vrai ~/osint
work="$(mktemp -d)"
trap 'kill "${pid:-0}" 2>/dev/null || true; rm -rf "$work"' EXIT

echo "== --help"
"$img" --help

echo "== interpréteur vu par l'application (ne doit pas être le .AppImage)"
"$img" -I -c '
import os, sys
sys.path.insert(0, os.environ["APPDIR"])
import audit_donnees_perso as o
print("sys.executable =", sys.executable)
assert not sys.executable.endswith(".AppImage"), "sys.executable pointe sur l AppImage"
for script, mod in (("maigret", "maigret"), ("sherlock", "sherlock_project")):
    cmd = o.tool_cmd(script, mod)
    print(mod, "->", cmd)
    assert cmd and cmd[0] == sys.executable
print("self_cmd =", o.self_cmd())
'

echo "== modules embarqués"
"$img" -I -c "import maigret, holehe, sherlock_project, fastapi, uvicorn; print('imports ok')"
"$img" -I -m maigret --version
"$img" -I -m sherlock_project --version

echo "== serveur (--serve, port 8300, 30 s max)"
(cd "$work" && "$img" --appimage-extract >/dev/null)
"$work/squashfs-root/AppRun" --serve &
pid=$!
ok=0
for _ in $(seq 30); do
    if curl -fsS http://127.0.0.1:8300/api/checklist >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
done
[ "$ok" = 1 ] && echo "serveur ok" || { echo "serveur KO"; exit 1; }
curl -fsS http://127.0.0.1:8300/favicon.png | head -c 4 | grep -q PNG && echo "icône (favicon) ok"
