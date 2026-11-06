#!/usr/bin/env bash
# Construit dist/audit-donnees-perso-windows-x86_64.exe (un seul fichier portable) + .sha256.
# À lancer sous Windows (Git Bash) depuis la racine du dépôt, avec Python 3.12 :
#   pip install -r appimage/requirements.txt pyinstaller==<version>
#   windows/build_exe.sh
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=audit-donnees-perso-windows-x86_64
python -I -m py_compile audit_donnees_perso.py windows/winmain.py
pyinstaller --noconfirm --clean --onefile \
  --name "$NAME" \
  --icon windows/icon.ico \
  --paths . \
  --collect-all maigret --collect-all sherlock_project --collect-all holehe \
  --collect-submodules uvicorn \
  --copy-metadata maigret --copy-metadata sherlock-project --copy-metadata holehe \
  windows/winmain.py
test -f "dist/$NAME.exe"
( cd dist && sha256sum "$NAME.exe" > "$NAME.exe.sha256" && ls -l "$NAME.exe" && cat "$NAME.exe.sha256" )
