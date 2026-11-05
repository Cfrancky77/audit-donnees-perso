#! /bin/bash
# Point d'entrée de l'AppImage (remplace AppRun). Sans argument : fenêtre autonome (--window).
# Autres usages : osint-audit-x86_64.AppImage --serve | --rescan | --install-launcher | --install-timer | --help
#   --serve : serveur seul (http://127.0.0.1:8300), sans ouvrir de fenêtre.
#
# On appelle l'interpréteur de opt/ directement, SANS le wrapper usr/bin/python3.X de
# python-appimage : ce wrapper exporte APPIMAGE_COMMAND, et Python met alors
# sys.executable = le fichier .AppImage. osint_app.py lance maigret/sherlock/holehe avec
# [sys.executable, "-I", "-m"/"-c", ...] : ils relanceraient l'AppImage au lieu de Python.
unset APPIMAGE_COMMAND

PY=""
for p in "$APPDIR"/opt/python3.*/bin/python3.[0-9]*; do
    case "$p" in *-config) continue ;; esac
    PY="$p"; break
done
if [ -z "$PY" ]; then
    echo "osint-audit : interpréteur Python introuvable dans $APPDIR/opt" >&2
    exit 1
fi

# Certificats TLS embarqués (comme le wrapper python-appimage), sauf si déjà fixés.
if [ -z "${SSL_CERT_FILE:-}" ] && [ -f "$APPDIR/opt/_internal/certs.pem" ]; then
    export SSL_CERT_FILE="$APPDIR/opt/_internal/certs.pem"
fi

# Défense : si l'AppImage est rappelée comme un interpréteur (python -I/-m/-c ...),
# transmettre à Python au lieu de l'application.
case "${1:-}" in
    -I|-m|-c|-u|-E|-s) exec "$PY" "$@" ;;
esac

if [ "$#" -eq 0 ]; then
    set -- --window
elif [ "$1" = "--serve" ]; then
    shift
fi
exec "$PY" -I "$APPDIR/osint_app.py" "$@"
