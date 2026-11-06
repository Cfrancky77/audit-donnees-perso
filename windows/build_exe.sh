#!/usr/bin/env bash
# Construit dist/audit-donnees-perso-windows-x86_64.exe (un seul fichier portable) + .sha256.
# À lancer sous Windows (Git Bash) depuis la racine du dépôt, avec Python 3.12 :
#   pip install -r appimage/requirements.txt pyinstaller==<version>
#   windows/build_exe.sh
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=audit-donnees-perso-windows-x86_64
python -I -m py_compile audit_donnees_perso.py windows/winmain.py

# Certains paquets (sherlock_project, charset_normalizer...) sont compilés avec mypyc : leur module
# d'exécution « <hash>__mypyc » est à la racine de site-packages et PyInstaller ne le voit pas.
HIDDEN=()
while IFS= read -r m; do
  m="${m%$'\r'}"   # Python écrit des fins de ligne Windows (\r\n)
  [ -n "$m" ] && HIDDEN+=(--hidden-import "$m")
done < <(python -I - <<'PY'
import glob, os, sysconfig
sp = sysconfig.get_paths()["purelib"]
for f in sorted(glob.glob(os.path.join(sp, "*__mypyc*"))):
    print(os.path.basename(f).split(".")[0])
PY
)
echo "modules mypyc ajoutés : ${HIDDEN[*]:-aucun}"
# user-scanner charge ses modules e-mail depuis les fichiers .py de user_scanner/email_scan
# (importlib, chemin sur disque) : il faut ces sources telles quelles dans l'exécutable.
US_DIR="$(python -I -c 'import os, user_scanner; print(os.path.dirname(user_scanner.__file__))')"
US_DIR="${US_DIR%$'\r'}"
pyinstaller --noconfirm --clean --onefile \
  --name "$NAME" \
  --icon windows/icon.ico \
  --paths . \
  --collect-all maigret --collect-all sherlock_project --collect-all holehe \
  --collect-all user_scanner --collect-all curl_cffi --add-data "$US_DIR/email_scan;user_scanner/email_scan" \
  --collect-submodules uvicorn \
  --copy-metadata maigret --copy-metadata sherlock-project --copy-metadata holehe --copy-metadata user-scanner \
  "${HIDDEN[@]}" \
  windows/winmain.py
test -f "dist/$NAME.exe"
( cd dist && sha256sum "$NAME.exe" > "$NAME.exe.sha256" && ls -l "$NAME.exe" && cat "$NAME.exe.sha256" )
