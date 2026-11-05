#!/usr/bin/env bash
# Construit osint-audit-x86_64.AppImage dans le dossier courant du dépôt.
# Prérequis : python3 + pip, libfuse2 (pour lancer l'AppImage), accès réseau (PyPI, GitHub).
#   pip install python-appimage==1.4.7
#   scripts/build_appimage.sh
# Variables facultatives :
#   PYTHON_VERSION (défaut 3.12)
#   BASE_IMAGE     chemin ou URL d'une image python-appimage précise
#                  (ex. .../python3.12.15-cp312-cp312-manylinux2014_x86_64.AppImage)
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
args=(build app -x osint_app.py)
if [ -n "${BASE_IMAGE:-}" ]; then
    args+=(-b "$BASE_IMAGE")
else
    args+=(-p "$PYTHON_VERSION")
fi

python -I -m py_compile osint_app.py
python-appimage "${args[@]}" appimage

out=osint-audit-x86_64.AppImage
test -x "$out"
sha256sum "$out" > "$out.sha256"
ls -lh "$out"
cat "$out.sha256"
