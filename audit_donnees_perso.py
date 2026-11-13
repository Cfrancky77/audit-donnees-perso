#!/usr/bin/env python3
"""
audit_donnees_perso.py — interface web locale pour auditer SES PROPRES données diffusées.

Fonctions :
  - plusieurs pseudos et plusieurs emails en un lancement
  - Maigret (pseudo -> comptes publics) et Holehe (email -> sites inscrits)
  - suivi en direct (progression par cible + journal)
  - rapport site par site (+ modèle de demande RGPD art. 15/17 par site)
  - historique des analyses, export JSON / CSV, annulation

Installation (poste fixe) :
  ./osint_check_pc.sh install          # crée ~/osint/venv avec maigret + holehe
  source ~/osint/venv/bin/activate
  pip install fastapi uvicorn sherlock-project
  python audit_donnees_perso.py                  # puis ouvrir http://127.0.0.1:8300
  python audit_donnees_perso.py --window         # fenêtre d'application autonome
  python audit_donnees_perso.py --install-launcher   # icône dans le menu des applications

Écoute sur 127.0.0.1 UNIQUEMENT (rapports = données perso agrégées).
À utiliser uniquement sur tes propres identifiants.
NON TESTÉ : le format exact des sorties Maigret/Holehe peut varier selon version.
"""
import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.request
import uuid
from collections import Counter
from datetime import date, datetime, timedelta
from urllib.parse import urlparse
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel

IS_WIN = sys.platform == "win32"
FROZEN = bool(getattr(sys, "frozen", False))  # exécutable Windows (PyInstaller)


def safe_chmod(path, mode):
    """Droits Unix ; sans effet utile sous Windows (le profil utilisateur est déjà privé)."""
    if IS_WIN:
        return
    os.chmod(path, mode)


# ------------------------------------------------------- Dossier de données
# Priorité : option --data-dir > variable OSINT_DATA_DIR > réglage enregistré
# (~/.config/audit-donnees-perso/settings.json, modifiable dans l'interface) > ~/osint.
DEFAULT_BASE = Path.home() / "osint"
if IS_WIN:
    SETTINGS_FILE = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "audit-donnees-perso" / "settings.json"
else:
    SETTINGS_FILE = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "audit-donnees-perso" / "settings.json"


LEGACY_SETTINGS_FILE = SETTINGS_FILE.parent.parent / "osint-audit" / "settings.json"  # ancien nom de l'application


def load_settings():
    """Lit les réglages ; reprend l'ancien fichier (osint-audit) tant que le nouveau n'existe pas."""
    for f in (SETTINGS_FILE, LEGACY_SETTINGS_FILE):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            return d if isinstance(d, dict) else {}
        except Exception:  # noqa: BLE001
            continue
    return {}


def save_settings(d):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(SETTINGS_FILE)


def _cli_data_dir(argv):
    """Lit --data-dir avant argparse (le dossier doit être connu dès le chargement du module)."""
    for i, a in enumerate(argv):
        if a == "--data-dir" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--data-dir="):
            return a.split("=", 1)[1]
    return None


def resolve_data_dir(argv=None):
    """Retourne (dossier, source) ; source = cli | env | settings | default."""
    for src, val in (("cli", _cli_data_dir(sys.argv[1:] if argv is None else argv)),
                     ("env", os.environ.get("OSINT_DATA_DIR")),
                     ("settings", load_settings().get("data_dir"))):
        if isinstance(val, str) and val.strip():
            return Path(val.strip()).expanduser().resolve(), src
    return DEFAULT_BASE, "default"


BASE, DATA_SOURCE = resolve_data_dir()
JOBS_DIR = BASE / "jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)
safe_chmod(BASE, 0o700)

# ------------------------------------------------------- Journal chronologique
# Une ligne JSON par événement dans <dossier de données>/journal.jsonl (ajout seul, jamais réécrit).
JOURNAL_FILE = BASE / "journal.jsonl"
JOURNAL_LOCK = threading.Lock()
JOURNAL_TYPES = ("analyse", "demande", "fuite", "checklist", "rapport", "réglage")


def journal(kind, text, ref=None, at=None, rebuilt=False):
    """Ajoute un événement. kind ∈ JOURNAL_TYPES ; ref = id de l'analyse / demande / fuite concernée."""
    ev = {"at": at or datetime.now().isoformat(timespec="seconds"), "type": kind, "text": str(text)[:300]}
    if ref:
        ev["ref"] = ref
    if rebuilt:
        ev["rebuilt"] = True
    try:
        with JOURNAL_LOCK, JOURNAL_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except OSError:
        pass  # le journal ne doit jamais faire échouer une action


def read_journal():
    out = []
    try:
        for line in JOURNAL_FILE.read_text(encoding="utf-8").splitlines():
            try:
                ev = json.loads(line)
                if isinstance(ev, dict) and ev.get("at") and ev.get("type"):
                    out.append(ev)
            except ValueError:
                continue
    except OSError:
        pass
    return out
BIN = Path(sys.executable).parent  # binaires du venv (repli si l'appel par « python -m » est impossible)


def load_config():
    """Réglages facultatifs : ~/osint/config.json, par ex. {"ollama_url": "http://mon-serveur:11434"}."""
    try:
        d = json.loads((BASE / "config.json").read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


# Assistant IA : un Ollama (local par défaut). Priorité : variable OLLAMA_URL > config.json
# (modifiable dans l'interface) > localhost.
def ollama_url():
    return str(os.environ.get("OLLAMA_URL") or load_config().get("ollama_url") or "http://127.0.0.1:11434").rstrip("/")


OLLAMA_URL = ollama_url()


def py_prefix():
    """Début de commande pour lancer du Python. Dans l'exécutable Windows, sys.executable est
    l'application elle-même : elle sait exécuter « --py -m module » et « --py -c code » (winmain.py)."""
    return [sys.executable, "--py"] if FROZEN else [sys.executable, "-I"]


def tool_cmd(script, module):
    """Commande pour lancer un outil avec l'interpréteur courant (« python -I -m »), ce qui marche
    aussi bien dans un venv que dans un AppImage. Repli : le script du dossier bin. None si absent."""
    import importlib.util
    if FROZEN or importlib.util.find_spec(module):
        return py_prefix() + ["-m", module]
    exe = BIN / script
    return [str(exe)] if exe.exists() else None


def self_cmd():
    """Commande qui relance cette application (AppImage ou script Python)."""
    ai = os.environ.get("APPIMAGE")
    if ai and Path(ai).exists():
        return [ai]
    if FROZEN:
        return [sys.executable]
    return [sys.executable, str(Path(__file__).resolve())]


def self_cmd_data():
    """self_cmd() + --data-dir quand le dossier vient de l'option ou de la variable : le menu et
    systemd ne voient ni l'une ni l'autre. Le réglage enregistré, lui, est relu au démarrage."""
    extra = ["--data-dir", str(BASE)] if DATA_SOURCE in ("cli", "env") else []
    return self_cmd() + extra


def quote_cmd(cmd):
    return " ".join('"' + c.replace('"', '\\"') + '"' for c in cmd)

RE_PSEUDO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-{}?]{1,63}$")  # {?} = variantes Sherlock
RE_MAIL = re.compile(r"^[A-Za-z0-9][^@\s]{0,63}@[^@\s]{1,255}\.[^@\s]{2,}$")
RE_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

JOBS = {}
PROCS = {}
LOCK = threading.Lock()


# ---------------------------------------------------------------- utilitaires
def save_job(job):
    d = JOBS_DIR / job["id"]
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "job.json.tmp"
    tmp.write_text(json.dumps(job, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(d / "job.json")


def log(job, msg):
    line = RE_ANSI.sub("", msg).rstrip()
    if not line:
        return
    job["last_activity"] = time.time()
    job["log"].append(time.strftime("%H:%M:%S ") + line[:300])
    if len(job["log"]) > 400:
        del job["log"][:100]


def add_warn(target, msg):
    target["warn"] = (target["warn"] + " · " if target.get("warn") else "") + msg


def stop_tree(proc, force=False):
    """Arrête un outil et ses sous-processus (groupe de processus sous Unix, taskkill /T sous Windows)."""
    if IS_WIN:
        cmd = ["taskkill", "/PID", str(proc.pid), "/T"] + (["/F"] if force else [])
        try:
            subprocess.run(cmd, capture_output=True, check=False, creationflags=subprocess.CREATE_NO_WINDOW)
        except OSError:
            pass
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL if force else signal.SIGTERM)
    except ProcessLookupError:
        pass


class Out(str):
    """Sortie d'une commande ; .timeout vaut True si la durée maximale a été atteinte."""
    timeout = False


def run_cmd(job, cmd, cwd, max_s=None, env_extra=None, no_stdin=False):
    """Lance une commande, relaie la sortie dans le journal.
    Retourne (code, sortie). Si max_s est dépassé : arrêt propre (SIGTERM puis SIGKILL), sortie.timeout=True.
    no_stdin : entrée vide, pour qu'un outil qui pose une question ne bloque jamais."""
    env = dict(os.environ, NO_COLOR="1", PYTHONUNBUFFERED="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8",
               **(env_extra or {}))
    if IS_WIN:
        extra = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW}
    else:
        extra = {"start_new_session": True}
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL if no_stdin else None,
        **extra,
    )
    PROCS[job["id"]] = proc
    state = {"timeout": False}
    timers = []

    def _kill():
        if proc.poll() is None:
            stop_tree(proc, force=True)

    def _term():
        if proc.poll() is None:
            state["timeout"] = True
            log(job, f"Durée maximale atteinte ({max_s / 60:g} min) : arrêt de l'outil, résultats partiels conservés")
            stop_tree(proc, force=IS_WIN)
            k = threading.Timer(8, _kill)
            k.daemon = True
            k.start()
            timers.append(k)

    if max_s:
        t = threading.Timer(max_s, _term)
        t.daemon = True
        t.start()
        timers.append(t)
    out = []
    try:
        for line in proc.stdout:
            out.append(line)
            log(job, line)
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            _kill()
            proc.wait()
    finally:
        for t in timers:
            t.cancel()
        PROCS.pop(job["id"], None)
    res = Out("".join(out))
    res.timeout = state["timeout"]
    return proc.returncode, res


RE_HIT = re.compile(r"^\s*\[\+\]\s*(.+?):\s*(https?://\S+)")


def salvage_hits(out, source):
    """Reconstruit des résultats depuis les lignes « [+] Site: URL » de la sortie (outil interrompu)."""
    res, seen = [], set()
    for line in RE_ANSI.sub("", str(out)).splitlines():
        m = RE_HIT.match(line)
        if m and m.group(2) not in seen:
            seen.add(m.group(2))
            res.append({"source": source, "site": m.group(1).strip(), "url": m.group(2), "tags": [], "infos": {}})
    return res


def status_is_claimed(st):
    """Le rapport 'simple' de Maigret ne liste que les comptes trouvés : on garde tout,
    sauf un statut explicitement négatif. (Ancienne version : exigeait le mot 'claimed'.)"""
    if isinstance(st, dict):
        st = st.get("status", "")
    s = str(st).strip().lower()
    if s in ("", "none"):
        return True
    return not any(w in s for w in ("available", "unknown", "illegal", "unclaimed"))


# ------------------------------------------------------------------- Maigret
def run_maigret(job, target, workdir):
    opts = job["options"]
    exe = tool_cmd("maigret", "maigret")
    if not exe:
        target["error"] = "maigret non installé"
        log(job, "Maigret introuvable : pip install maigret")
        return []
    base = exe + [target["value"], "--folderoutput", str(workdir),
            "--json", "simple", "--timeout", str(opts["timeout"])]
    base += ["-a"] if opts["all_sites"] else ["--top-sites", str(opts["top_sites"])]
    extra = ["--no-progressbar", "--no-color"]
    ms = opts.get("max_min", 20) * 60
    code, out = run_cmd(job, base + extra, workdir, ms)
    if code == 2 and not out.timeout:  # option inconnue sur cette version -> relance minimale
        log(job, "Maigret : options optionnelles refusées, relance minimale")
        code, out = run_cmd(job, base, workdir, ms)
    if code not in (0, None) and not out.timeout:
        target["error"] = f"maigret code {code}"
    results = []
    files = sorted(workdir.glob("report_*.json"))
    if not files:
        if out.timeout:
            # Maigret n'écrit son rapport qu'à la fin : on récupère les comptes affichés dans le journal
            results = salvage_hits(out, "maigret")
            add_warn(target, f"maigret interrompu après {opts.get('max_min', 20):g} min : "
                             f"{len(results)} compte(s) partiels, sans détails de profil")
            return results
        target["error"] = target.get("error") or "aucun fichier JSON Maigret trouvé"
        return results
    data = json.loads(files[-1].read_text(encoding="utf-8", errors="replace"))
    if isinstance(data, list):  # variante : liste d'objets avec "sitename"
        data = {str(x.get("sitename") or (x.get("site") or {}).get("name") or i): x
                for i, x in enumerate(data) if isinstance(x, dict)}
    log(job, f"Maigret : {files[-1].name}, {len(data) if isinstance(data, dict) else '?'} entrée(s)")
    if isinstance(data, dict) and data:
        k0 = next(iter(data))
        d0 = data[k0] if isinstance(data[k0], dict) else {}
        log(job, f"Maigret : exemple {k0!r} clés={sorted(d0)[:12]} status={str(d0.get('status'))[:80]!r}")
    for site, d in (data.items() if isinstance(data, dict) else []):
        if not isinstance(d, dict):
            continue
        st = d.get("status")
        if not status_is_claimed(st):
            continue
        infos, tags = {}, []
        if isinstance(st, dict):
            ids = st.get("ids") or {}
            if isinstance(ids, dict):
                infos.update({str(k): str(v) for k, v in ids.items() if v not in (None, "", [])})
            tags = [str(t) for t in (st.get("tags") or [])]
        for k, v in (d.get("ids_data") or {}).items() if isinstance(d.get("ids_data"), dict) else []:
            if v not in (None, "", []):
                infos[str(k)] = str(v)
        results.append({
            "source": "maigret", "site": str(site),
            "url": str(d.get("url_user") or d.get("url_main") or ""),
            "tags": tags, "infos": infos,
        })
    return results


# ------------------------------------------------------------------ Sherlock
def run_sherlock(job, target, workdir):
    """Sherlock : pseudo -> URLs de comptes (pas d'infos de profil). {?} = variantes _ - ."""
    opts = job["options"]
    exe = tool_cmd("sherlock", "sherlock_project")
    if not exe:
        add_warn(target, "sherlock non installé : pip install sherlock-project")
        log(job, "Sherlock absent, étape ignorée (pip install sherlock-project)")
        return []
    sdir = workdir / "sherlock"
    sdir.mkdir(exist_ok=True)
    cmd = exe + [target["value"], "--csv", "--folderoutput", str(sdir),
           "--timeout", str(opts["timeout"]), "--print-found", "--no-color"]
    if opts.get("nsfw"):
        cmd.append("--nsfw")
    code, out = run_cmd(job, cmd, sdir, opts.get("max_min", 20) * 60)
    if out.timeout:
        add_warn(target, f"sherlock interrompu après {opts.get('max_min', 20):g} min : résultats partiels")
    elif code not in (0, None):
        add_warn(target, f"sherlock code {code}")
    results, seen = [], set()
    # 1) CSV si présent
    for f in sorted(sdir.glob("*.csv")):
        with f.open(encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                if str(row.get("exists", "")).strip().lower() != "claimed":
                    continue
                url = str(row.get("url_user") or "")
                if url and url not in seen:
                    seen.add(url)
                    results.append({"source": "sherlock", "site": str(row.get("name") or url),
                                    "url": url, "tags": [], "infos": {}})
    # 2) repli : lignes "[+] Site: https://..." de la sortie
    if not results:
        for line in out.splitlines():
            m = re.match(r"^\s*\[\+\]\s*(.+?):\s*(https?://\S+)", RE_ANSI.sub("", line))
            if m and m.group(2) not in seen:
                seen.add(m.group(2))
                results.append({"source": "sherlock", "site": m.group(1).strip(),
                                "url": m.group(2), "tags": [], "infos": {}})
    return results


def norm_url(u):
    return re.sub(r"^https?://(www\.)?", "", str(u).lower()).rstrip("/")


def merge_results(primary, extra):
    """Fusionne sans doublon : une URL trouvée par les deux outils reçoit source 'maigret+sherlock'."""
    index = {norm_url(r["url"]): r for r in primary if r["url"]}
    for r in extra:
        k = norm_url(r["url"])
        if k in index:
            if r["source"] not in index[k]["source"]:
                index[k]["source"] += "+" + r["source"]
        else:
            primary.append(r)
    return primary


# -------------------------------------------------------------------- Holehe
RE_HOLEHE_LINE = re.compile(r"^\[([+\-x])\] ([A-Za-z0-9._\-]+)\s*$")  # la légende (avec espaces) ne correspond pas


# Au-delà de cette part de sites non testables, le test Holehe est « dégradé » : un « aucun compte »
# n'a plus de valeur. 30 % : en temps normal quelques sites seulement limitent le débit.
COV_DEGRADED = 0.30


def coverage_degraded(cov):
    """True si trop de sites Holehe n'ont pas pu être testés pour conclure quoi que ce soit."""
    return bool(cov and cov.get("total")) and cov.get("blocked", 0) / cov["total"] >= COV_DEGRADED


def degraded_msg(cov):
    pc = round(100 * cov["blocked"] / cov["total"])
    return f"test dégradé : {pc} % des sites non testables ({cov['blocked']}/{cov['total']}), ne conclus rien"


def holehe_coverage(out):
    """Compte [+] compte trouvé, [-] pas de compte, [x] site non testable (limite de débit / blocage)."""
    groups = {"+": [], "-": [], "x": []}
    for raw in RE_ANSI.sub("", out).splitlines():
        for part in raw.split("\r"):
            m = RE_HOLEHE_LINE.match(part.strip())
            if m:
                groups[m.group(1)].append(m.group(2))
    total = sum(len(v) for v in groups.values())
    if not total:
        return None  # format de sortie inattendu : on n'invente pas de couverture
    return {"total": total, "used": len(groups["+"]), "unused": len(groups["-"]),
            "blocked": len(groups["x"]), "blocked_sites": sorted(set(groups["x"]))}


# Holehe appelle pypi.org au démarrage (check_update) sans gérer l'échec : si pypi est injoignable
# (DNS, VPN, délai TLS), il plante AVANT de tester le moindre site (vu : ConnectError / ConnectTimeout).
# Ce lanceur désactive uniquement cette vérification de mise à jour, le reste est inchangé.
HOLEHE_WRAPPER = ("import sys\nimport holehe.core as c\n"
                  "c.check_update = lambda *a, **k: None\n"
                  "sys.exit(c.main())\n")


def run_holehe(job, target, workdir):
    # sans --only-used : on a besoin des lignes [-] et [x] pour mesurer la couverture réelle
    # -I : n'ajoute pas le dossier courant à sys.path (sinon un dossier « osint » local masque le
    # sous-paquet holehe.modules.osint et Holehe plante) ; -u : sortie non bufferisée
    base = py_prefix() + ["-u", "-c", HOLEHE_WRAPPER, target["value"], "-C"]
    HM = 180  # Holehe termine normalement en quelques secondes : 3 min max
    code, out = run_cmd(job, base + ["--no-color", "--no-clear"], workdir, HM)
    if code == 2 and not out.timeout:
        log(job, "Holehe : options optionnelles refusées, relance minimale")
        code, out = run_cmd(job, base, workdir, HM)
    # échec DNS passager : une nouvelle tentative après pause
    for essai in range(2):
        if code in (0, None) or out.timeout or "name resolution" not in out.lower():
            break
        log(job, f"Holehe : DNS indisponible, nouvelle tentative dans 10 s ({essai + 1}/2)")
        time.sleep(10)
        for old in workdir.glob("*.csv"):
            old.unlink()
        code, out = run_cmd(job, base, workdir, HM)
    results = []
    files = sorted(workdir.glob("*.csv"))
    if not files:
        # pas de CSV = le scan n'est pas allé au bout : là seulement c'est une erreur
        lines = [l.strip() for l in RE_ANSI.sub("", out).splitlines()
                 if l.strip() and not re.search(r"\d+/\d+ \[", l)]  # ignore la barre de progression
        if out.timeout:
            target["error"] = "holehe interrompu après 3 min, aucun résultat exploitable"
            return results
        target["error"] = (f"holehe code {code}" if code not in (0, None) else "holehe") + \
            (f" : {lines[-1][:120]}" if lines else " : aucun CSV produit")
        return results
    if code not in (0, None):  # vu en vrai : code 1 alors que le scan est complet et le CSV écrit
        log(job, f"Holehe : code de sortie {code} mais CSV présent, scan considéré comme complet")
    cov = holehe_coverage(out)
    target["coverage"] = cov
    if cov:
        log(job, f"Holehe couverture : {cov['total']} sites, {cov['used']} compte(s), "
                 f"{cov['unused']} sans compte, {cov['blocked']} non testables")
        cov["degraded"] = coverage_degraded(cov)
        if cov["degraded"]:
            add_warn(target, degraded_msg(cov))
    with files[-1].open(encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            if str(row.get("exists", "")).strip().lower() != "true":
                continue
            infos = {}
            for key, label in (("emailrecovery", "email de récupération (masqué)"),
                               ("phoneNumber", "téléphone (masqué)"),
                               ("others", "autres")):
                v = str(row.get(key, "")).strip()
                if v and v.lower() not in ("none", "false", "nan"):
                    infos[label] = v
            domain = str(row.get("domain") or row.get("name") or "")
            results.append({
                "source": "holehe", "site": str(row.get("name") or domain),
                "url": f"https://{domain}" if domain else "",
                "tags": [], "infos": infos,
            })
    return results


# -------------------------------------------------------------- user-scanner (essai)
# Réglages imposés : pas de vérification/installation de mise à jour, jamais d'envoi à Hudson Rock
# sans question (et --hudson n'est jamais passé), modules « bruyants » (qui envoient un e-mail de
# réinitialisation au titulaire) jamais lancés : sans --allow-loud ils sont « Skipped ».
US_CONFIG = {"auto_update_status": False, "auto_hudson_prompt": True, "auto_loud_single_module_prompt": True}


def us_coverage(items):
    """Registered / Not Registered / Error / Skipped. Skipped = modules volontairement non lancés
    (ils préviendraient le titulaire) : exclus du total, comptés à part."""
    st = [str(x.get("status", "")) for x in items]
    if not st:
        return None
    blocked = sorted({str(x.get("site_name", "?")) for x in items if x.get("status") == "Error"})
    total = sum(1 for v in st if v != "Skipped")
    if not total:
        return None
    return {"total": total, "used": st.count("Registered"), "unused": st.count("Not Registered"),
            "blocked": st.count("Error"), "blocked_sites": blocked, "skipped": st.count("Skipped")}


def run_user_scanner(job, target, workdir):
    opts = job["options"]
    cfg = workdir / "user-scanner-config.json"
    cfg.write_text(json.dumps(US_CONFIG), encoding="utf-8")
    out_json = workdir / "user-scanner.json"
    cmd = py_prefix() + ["-m", "user_scanner", "-e", target["value"], "--all", "-f", "json", "-o", str(out_json)]
    if not opts.get("nsfw"):
        cmd.append("--no-nsfw")
    code, out = run_cmd(job, cmd, workdir, 300, env_extra={"USER_SCANNER_CONFIG": str(cfg)}, no_stdin=True)
    try:
        items = json.loads(out_json.read_text(encoding="utf-8"))
        if not isinstance(items, list):
            raise ValueError("format inattendu")
    except Exception as e:  # noqa: BLE001
        add_warn(target, "user-scanner interrompu après 5 min" if out.timeout else
                 f"user-scanner : aucun résultat lisible (code {code}, {type(e).__name__})")
        return []
    cov = us_coverage(items)
    target["coverage_us"] = cov
    if cov:
        log(job, f"user-scanner couverture : {cov['total']} sites, {cov['used']} compte(s), {cov['unused']} sans compte, "
                 f"{cov['blocked']} non testables, {cov['skipped']} écartés (envoient un e-mail)")
        cov["degraded"] = coverage_degraded(cov)
        if cov["degraded"]:
            add_warn(target, "user-scanner " + degraded_msg(cov))
    res = []
    for x in items:
        if x.get("status") != "Registered":
            continue
        extra = x.get("extra") if isinstance(x.get("extra"), dict) else {}
        infos = {str(k)[:40]: str(v)[:200] for k, v in list(extra.items())[:8] if v not in (None, "", [], {})}
        url = str(x.get("url") or "")
        res.append({"source": "user-scanner", "site": str(x.get("site_name") or "?"),
                    "url": url if re.match(r"^https?://", url) else "", "tags": [], "infos": infos})
    return res


def merge_email_results(a, b):
    """Holehe + user-scanner : un site trouvé par les deux n'apparaît qu'une fois (sources fusionnées)."""
    key = lambda r: re.sub(r"[^a-z0-9]", "", r["site"].lower().split(".")[0])
    out, idx = [], {}
    for r in a + b:
        k = key(r)
        if k in idx:
            prev = out[idx[k]]
            if r["source"] not in prev["source"]:
                prev["source"] += "+" + r["source"]
            prev["infos"] = {**r["infos"], **prev["infos"]}
            prev["url"] = prev["url"] or r["url"]
        else:
            idx[k] = len(out)
            out.append(dict(r))
    return out


# ------------------------------------------------------------------ Orchestre
JOB_SLOT = threading.Semaphore(1)  # une seule analyse à la fois (CPU, limites de débit des sites)


STATE_FR = {"terminé": "terminée", "annulé": "annulée", "interrompu": "interrompue"}


def targets_label(job):
    n_p = sum(1 for t in job["targets"] if t["kind"] == "pseudo")
    n_m = len(job["targets"]) - n_p
    parts = ([f"{n_p} pseudo" + ("s" if n_p > 1 else "")] if n_p else []) + ([f"{n_m} email" + ("s" if n_m > 1 else "")] if n_m else [])
    return ", ".join(parts) or "aucune cible"


def run_job(job):
    if not JOB_SLOT.acquire(blocking=False):
        job["state"] = "queued"
        log(job, "Une autre analyse est en cours : celle-ci attend son tour")
        save_job(job)
        JOB_SLOT.acquire()
    try:
        _run_job(job)
    finally:
        JOB_SLOT.release()


def _run_job(job):
    job["state"] = "running"
    save_job(job)
    total = len(job["targets"])
    # emails d'abord : Holehe est plus fragile après la salve de requêtes Maigret/Sherlock
    order = sorted(range(total), key=lambda k: job["targets"][k]["kind"] != "email")
    for n_done, i in enumerate(order, 1):
        t = job["targets"][i]
        if job.get("cancel"):
            t["status"] = "annulé"
            continue
        t["status"] = "en cours"
        t["started"] = time.time()
        log(job, f"=== {t['kind']} : {t['value']} ({i + 1}/{total}) ===")
        workdir = JOBS_DIR / job["id"] / f"t{i}"
        workdir.mkdir(parents=True, exist_ok=True)
        try:
            if t["kind"] == "pseudo":
                res, n_m, n_s = [], None, None
                if "{?}" not in t["value"]:  # variantes = Sherlock seul
                    res = run_maigret(job, t, workdir)
                    n_m = len(res)
                if job["options"].get("sherlock", True) and not job.get("cancel"):
                    sh = run_sherlock(job, t, workdir)
                    n_s = len(sh)
                    res = merge_results(res, sh)
                log(job, f"Bilan {t['value']} : maigret={n_m} sherlock={n_s} fusionné={len(res)}")
                if n_m == 0 and not t.get("error"):
                    add_warn(t, "maigret : 0 résultat")
                t["results"] = res
            else:
                res = run_holehe(job, t, workdir)
                if job["options"].get("user_scanner") and not job.get("cancel"):
                    us = run_user_scanner(job, t, workdir)
                    log(job, f"Bilan {t['value']} : holehe={len(res)} user-scanner={len(us)}")
                    res = merge_email_results(res, us)
                t["results"] = res
            t["status"] = "annulé" if job.get("cancel") else ("erreur" if t.get("error") and not t["results"] else "terminé")
        except Exception as e:  # noqa: BLE001
            t["status"] = "erreur"
            t["error"] = f"{type(e).__name__}: {e}"
            t["results"] = t.get("results", [])
        t["finished"] = time.time()
        job["done"] = n_done
        save_job(job)
    job["state"] = "annulé" if job.get("cancel") else "terminé"
    job["finished"] = time.time()
    log(job, "Analyse " + job["state"])
    save_job(job)
    found = sum(len(t.get("results", [])) for t in job["targets"])
    errs = sum(1 for t in job["targets"] if t.get("status") == "erreur")
    mins = max(1, round((job["finished"] - job["created"]) / 60))
    journal("analyse", f"Analyse {STATE_FR.get(job['state'], job['state'])} : {found} compte(s) trouvé(s) en {mins} min"
            + (f", {errs} cible(s) en erreur" if errs else ""), job["id"])


def load_jobs():
    for p in JOBS_DIR.glob("*/job.json"):
        try:
            j = json.loads(p.read_text(encoding="utf-8"))
            if j.get("state") in ("running", "queued"):
                j["state"] = "interrompu"
            JOBS[j["id"]] = j
        except Exception:  # noqa: BLE001
            pass


# -------------------------------------------------------------------- Analyse
# Analyse déterministe (sans IA) : catégorie, sensibilité, correspondance avec toi,
# données exposées, priorité, explication et action conseillée pour chaque compte.
SENS_ORDER = ["adulte", "rencontre", "santé", "finance / crypto"]
MID_CATS = {"réseau social", "messagerie", "vidéo / streaming", "professionnel", "photo / art",
            "forum", "jeux", "blog", "achats"}
TAG_MAP = {
    "porn": "adulte", "webcam": "adulte", "erotic": "adulte", "dating": "rencontre",
    "health": "santé", "medicine": "santé",
    "crypto": "finance / crypto", "finance": "finance / crypto", "trading": "finance / crypto", "bank": "finance / crypto",
    "social": "réseau social", "messaging": "messagerie",
    "video": "vidéo / streaming", "streaming": "vidéo / streaming", "movies": "vidéo / streaming",
    "photo": "photo / art", "art": "photo / art", "gaming": "jeux", "coding": "dev / tech", "tech": "dev / tech",
    "forum": "forum", "shopping": "achats", "music": "musique", "blog": "blog",
    "business": "professionnel", "jobs": "professionnel", "news": "actualités", "education": "éducation",
}
SITE_KW = [
    ("adulte", ["chaturbate", "onlyfans", "pornhub", "xvideos", "stripchat"]),
    ("rencontre", ["tinder", "meetic", "badoo", "okcupid", "grindr", "happn"]),
    ("santé", ["7cups", "doctissimo"]),
    ("finance / crypto", ["polymarket", "binance", "coinbase", "paypal", "kraken", "revolut"]),
    ("messagerie", ["snapchat", "telegram", "discord", "whatsapp", "signal", "skype"]),
    ("réseau social", ["twitter", "instagram", "facebook", "threads", "tiktok", "mastodon", "pinterest", "tumblr", "houzz"]),
    ("vidéo / streaming", ["youtube", "twitch", "vimeo", "giphy", "dailymotion", "smule", "filmweb"]),
    ("professionnel", ["linkedin", "malt", "indeed", "viadeo"]),
    ("dev / tech", ["github", "gitlab", "stackoverflow", "codepen", "apple developer", "sketchfab", "replit"]),
    ("jeux", ["steam", "xbox", "roblox", "chess", "epic games"]),
    ("photo / art", ["flickr", "500px", "fredmiranda", "deviantart", "behance", "artstation"]),
    ("forum", ["reddit", "forum", "librarything"]),
    ("sécurité / fuites", ["hudsonrock", "haveibeenpwned"]),
]
FIELD_LABELS = {  # clé en minuscules -> (libellé, sensible ?)
    "fullname": ("nom affiché", True), "full_name": ("nom affiché", True), "name": ("nom affiché", True),
    "username": ("pseudo", False),
    "image": ("photo de profil", True), "avatar": ("photo de profil", True), "profile_image": ("photo de profil", True),
    "bio": ("biographie", True), "description": ("biographie", True),
    "created_at": ("date de création du compte", False), "registered": ("date de création du compte", False),
    "uid": ("identifiant interne", False), "id": ("identifiant interne", False),
    "follower_count": ("audience / activité", False), "following_count": ("audience / activité", False),
    "favourites_count": ("audience / activité", False), "posts_count": ("audience / activité", False),
    "location": ("localisation", True), "country": ("localisation", True), "city": ("localisation", True),
    "email": ("email", True), "phone": ("téléphone", True),
    "birthday": ("date de naissance", True), "age": ("âge", True), "gender": ("genre", True),
    "website": ("lien externe", False), "links": ("lien externe", False),
}
SKIP_FIELDS = {"url", "is_protected", "profile_type", "snapcode_image", "is_verified"}
NAME_KEYS = ("fullname", "full_name", "name")
MATCH_PTS = {"confirmé": 4, "probable": 4, "possible": 3, "inconnu": 2, "improbable": 0}
MATCH_LABEL = {"confirmé": "confirmé (lié à ton email)", "probable": "probable", "possible": "possible",
               "inconnu": "non comparable", "improbable": "improbable (nom différent)"}


def _norm(s):
    s = unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", " ", s).strip()


def categorize(r):
    text = _norm(f"{r.get('site', '')} {r.get('url', '')}")
    kw = next((cat for cat, words in SITE_KW if any(_norm(w) in text for w in words)), None)
    tag_cats = [TAG_MAP[t.lower()] for t in r.get("tags", []) if t.lower() in TAG_MAP]
    if kw in SENS_ORDER:
        return kw
    for c in SENS_ORDER:
        if c in tag_cats:
            return c
    return kw or (tag_cats[0] if tag_cats else "autre")


def sensitivity(cat):
    return "élevée" if cat in SENS_ORDER else "moyenne" if cat in MID_CATS else "faible"


def field_summary(infos):
    labels, risky = [], []
    for k, v in infos.items():
        kl = str(k).lower()
        if kl in SKIP_FIELDS or kl.startswith("_") or v in (None, "", "None"):
            continue  # clés internes de Maigret (ex. _extractor) : sans intérêt pour toi
        if kl in FIELD_LABELS:
            lab, sens = FIELD_LABELS[kl]
        elif kl.endswith("_count") or kl in ("followers", "following"):
            lab, sens = "audience / activité", False
        else:
            lab, sens = str(k), ("téléphone" in kl or "récupération" in kl)
        if lab not in labels:
            labels.append(lab)
        if sens and lab not in risky:
            risky.append(lab)
    return labels, risky


def match_level(kind, infos, ident):
    if kind == "email":
        return "confirmé"
    first, last = _norm(ident.get("first", "")), _norm(ident.get("last", ""))
    names = [str(v) for k, v in infos.items() if str(k).lower() in NAME_KEYS]
    if (not first and not last) or not names:
        return "inconnu"
    toks = set(_norm(" ".join(names)).split())
    f = bool(first) and all(t in toks for t in first.split())
    l = bool(last) and all(t in toks for t in last.split())
    return "probable" if f and l else "possible" if (f or l) else "improbable"


def build_item(t, r, ident):
    infos = r.get("infos") or {}
    cat = categorize(r)
    sens = sensitivity(cat)
    match = match_level(t["kind"], infos, ident)
    fields, risky = field_summary(infos)
    names = [str(v) for k, v in infos.items() if str(k).lower() in NAME_KEYS]
    pts = MATCH_PTS[match] + {"élevée": 1, "moyenne": 0.5, "faible": 0}[sens] + 0.5 * len(risky)
    level = "prioritaire" if pts >= 4.5 else "à vérifier" if pts >= 2 else "faible"
    special = cat == "sécurité / fuites"
    if special:
        level = "à vérifier"
    site = r.get("site", "?")
    # --- explication
    if special:
        explain = (f"{site} est un service de vérification de fuites. Sherlock le compte « trouvé » dès que la page "
                   "répond : cela ne prouve PAS que ton pseudo a fuité.")
        action = "Ouvre le lien toi-même et lis le résultat renvoyé (nombre de fuites éventuelles)."
    else:
        parts = [f"Compte détecté sur {site} (catégorie : {cat}, sensibilité {sens})."]
        if t["kind"] == "email":
            parts.append("Ce site a un compte associé à ton adresse email.")
        elif names and (ident.get("first") or ident.get("last")):
            parts.append(f"Nom affiché : « {names[0]} » → correspondance {match} avec le prénom/nom saisi.")
        elif names:
            parts.append(f"Nom affiché : « {names[0]} ». Renseigne ton prénom/nom (colonne de gauche) "
                         "pour estimer si ce profil est le tien.")
        elif not (ident.get("first") or ident.get("last")):
            parts.append("Renseigne ton prénom/nom (colonne de gauche) pour estimer si ce profil est le tien.")
        else:
            parts.append("Aucun nom public détecté : impossible de dire à qui appartient ce compte.")
        if risky:
            parts.append("Visible publiquement : " + ", ".join(risky) + ".")
        explain = " ".join(parts)
        if match == "confirmé":
            action = ("Si tu n'utilises plus ce compte, supprime-le. S'il n'y a pas d'option de suppression, "
                      "envoie la demande RGPD (art. 17) du bouton « Demande RGPD » dans le détail.")
        elif match in ("probable", "possible"):
            action = ("Ouvre la page et vérifie si c'est ton compte. Si oui : passe-le en privé, retire les infos "
                      "inutiles ou supprime-le. Si non : homonyme, à ignorer (à signaler seulement si quelqu'un se fait passer pour toi).")
        elif match == "improbable":
            action = "Le nom affiché ne correspond pas au tien : probablement un homonyme. Ignore, sauf si la page est la tienne."
        else:
            action = "Ouvre la page pour vérifier. Un pseudo identique ne prouve pas que ce compte est à toi."
        if sens == "élevée" and match != "improbable":
            action += " Catégorie sensible : si le compte est le tien, traite-le en premier ; sinon vérifie qu'on n'usurpe pas ton identité."
    return {
        "target": t["value"], "kind": t["kind"], "site": site, "url": r.get("url", ""),
        "source": r.get("source", ""), "category": cat, "sensitivity": sens,
        "match": match, "match_label": (MATCH_LABEL[match] if match != "inconnu" else
                  ("non comparable (aucun nom sur le profil)" if (ident.get("first") or ident.get("last"))
                   else "non comparable (identité non saisie)")), "level": level,
        "css": {"prioritaire": "prio", "à vérifier": "verif", "faible": "faible"}[level],
        "score": round(pts, 1), "fields": fields, "risky": risky, "names": names,
        "explain": explain, "action": action,
    }


def analyze_job(job, ident):
    items = [build_item(t, r, ident) for t in job["targets"] for r in t.get("results", [])]
    items.sort(key=lambda x: (-x["score"], x["site"].lower()))
    by_level = Counter(i["level"] for i in items)
    fields = Counter(f for i in items for f in i["fields"] if f not in ("pseudo", "identifiant interne"))
    summary = {
        "total": len(items),
        "by_category": dict(Counter(i["category"] for i in items)),
        "by_match": dict(Counter(i["match_label"] for i in items)),
        "by_level": dict(by_level),
        "exposed_fields": dict(fields.most_common(8)),
        "sensitive": sum(1 for i in items if i["sensitivity"] == "élevée" and i["match"] != "improbable"),
    }
    plan = []
    prio = [i for i in items if i["level"] == "prioritaire"]
    if prio:
        plan.append(f"Vérifie en priorité {len(prio)} compte(s) : " + ", ".join(dict.fromkeys(i["site"] for i in prio[:6])) +
                    ". Ouvre chaque page et confirme si c'est le tien.")
    if summary["sensitive"]:
        plan.append(f"{summary['sensitive']} compte(s) de catégorie sensible dont la correspondance n'est pas écartée : "
                    "à vérifier même s'ils ne sont pas à toi (usurpation possible).")
    n_mail = sum(1 for i in items if i["kind"] == "email")
    if n_mail:
        plan.append(f"{n_mail} site(s) ont un compte lié à ton email : supprime ceux que tu n'utilises plus.")
    for t in job["targets"]:
        for tool, c in (("Holehe", t.get("coverage")), ("user-scanner", t.get("coverage_us"))):
            if coverage_degraded(c):
                plan.append(f"{tool} pour {t['value']} : {degraded_msg(c)}. "
                            "« Aucun compte » ne prouve rien. Vérifie à la main les sites bloqués (liste dans le rapport).")
    if fields:
        plan.append("Informations les plus visibles : " + ", ".join(list(fields)[:3]) + ".")
    if any(i["category"] == "sécurité / fuites" for i in items):
        plan.append("Ouvre le lien du service de fuites (ex. HudsonRock) et lis le résultat toi-même.")
    n_nc = sum(1 for i in items if i["match"] == "inconnu" and i["kind"] != "email" and i["category"] != "sécurité / fuites")
    if n_nc and (ident.get("first") or ident.get("last")):
        plan.append(f"{n_nc} compte(s) sans nom visible sur le profil : l'outil ne peut pas dire s'ils sont à toi. "
                    "Ouvre-les pour vérifier (photo, bio, pseudo identique ailleurs).")
    if not (ident.get("first") or ident.get("last")):
        plan.append("Renseigne ton prénom et ton nom pour que l'outil estime quels profils sont les tiens.")
    plan.append("Résultat incomplet : certains sites bloquent les scans (« Bot protection »). "
                "Complète avec HIBP et les vérifications manuelles.")
    leaks = load_leaks()
    summary["leaks"] = len(leaks)
    if leaks:
        plan.insert(0, f"{len(leaks)} fuite(s) connue(s) notée(s) à la main : " +
                    ", ".join(f"{x['service']}" + (f" ({x['date']})" if x.get("date") else "") for x in leaks[:6]) +
                    ". Détail et conseils dans la carte « Fuites connues ».")
    summary["plan"] = plan
    return {"summary": summary, "items": items, "identity": ident}


def clean_ident(first, last):
    return {"first": str(first or "")[:60].strip(), "last": str(last or "")[:60].strip()}


# ------------------------------------------------------------------ Assistant IA
def ollama_call(path, payload=None, timeout=600):
    req = urllib.request.Request(
        OLLAMA_URL + path, data=None if payload is None else json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def assistant_context(analysis):
    lines = []
    for i in analysis["items"][:80]:
        lines.append(f"- {i['site']} | cible {i['target']} | catégorie {i['category']} | sensibilité {i['sensitivity']} | "
                     f"correspondance {i['match_label']} | priorité {i['level']} | "
                     f"nom affiché {i['names'][0] if i['names'] else 'aucun'} | données visibles {', '.join(i['fields']) or 'aucune'}")
    for x in load_leaks():
        lines.append(f"- FUITE CONNUE (saisie manuelle) | service {x['service']} | adresse {x.get('address') or '?'} | "
                     f"date {x.get('date') or '?'} | données exposées {x.get('data') or 'non précisées'}")
    return "\n".join(lines) or "(aucun résultat)"


RE_THINK = re.compile(r"<think>.*?</think>", re.S)


CHECKLIST_FILE = BASE / "checklist.json"
CHECK_LOCK = threading.Lock()
RE_CHECK_ID = re.compile(r"^[a-z0-9_]{1,40}$")


def load_checks():
    try:
        d = json.loads(CHECKLIST_FILE.read_text(encoding="utf-8"))
        return {k: bool(v) for k, v in d.items() if isinstance(k, str)} if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


class CheckBody(BaseModel):
    id: str
    done: bool
    label: str = ""   # texte affiché, pour un journal lisible


class AskBody(BaseModel):
    question: str
    model: str
    history: list = []
    first: str = ""
    last: str = ""


# ------------------------------------------------------------------------ API
app = FastAPI(title="OSINT perso")


def new_job(pseudos, mails, o, idn):
    o = o if isinstance(o, dict) else {}
    options = {
        "all_sites": bool(o.get("all_sites", False)),
        "top_sites": max(50, min(int(o.get("top_sites", 500)), 3000)),
        "timeout": max(5, min(int(o.get("timeout", 20)), 120)),
        "max_min": max(2, min(int(o.get("max_min", 20)), 180)),
        "sherlock": bool(o.get("sherlock", True)),
        "nsfw": bool(o.get("nsfw", False)),
        "user_scanner": bool(o.get("user_scanner", False)),
    }
    identity = clean_ident(idn.get("first"), idn.get("last")) if isinstance(idn, dict) else clean_ident("", "")
    return {
        "id": uuid.uuid4().hex[:12], "created": time.time(), "state": "queued",
        "options": options, "identity": identity, "done": 0, "cancel": False, "log": [],
        "last_activity": time.time(),
        "targets": [{"kind": "pseudo", "value": p, "status": "en attente", "results": []} for p in pseudos]
                   + [{"kind": "email", "value": m, "status": "en attente", "results": []} for m in mails],
    }


@app.post("/api/jobs")
async def create_job(request: Request):
    if "application/json" not in request.headers.get("content-type", ""):
        raise HTTPException(415, "JSON requis")
    body = await request.json()
    pseudos = [p.strip() for p in body.get("pseudos", []) if p and p.strip()]
    mails = [m.strip() for m in body.get("emails", []) if m and m.strip()]
    pseudos = list(dict.fromkeys(pseudos))
    mails = list(dict.fromkeys(mails))
    bad = [p for p in pseudos if not RE_PSEUDO.match(p)] + [m for m in mails if not RE_MAIL.match(m)]
    if bad:
        raise HTTPException(400, "Valeurs invalides : " + ", ".join(bad[:5]))
    if not pseudos and not mails:
        raise HTTPException(400, "Aucune cible")
    if len(pseudos) + len(mails) > 30:
        raise HTTPException(400, "30 cibles maximum")
    job = new_job(pseudos, mails, body.get("options", {}), body.get("identity"))
    with LOCK:
        JOBS[job["id"]] = job
    save_job(job)
    journal("analyse", f"Analyse lancée : {targets_label(job)}", job["id"])
    threading.Thread(target=run_job, args=(job,), daemon=True).start()
    return {"id": job["id"]}


@app.get("/api/jobs")
def list_jobs():
    rows = [{"id": j["id"], "created": j["created"], "state": j["state"],
             "targets": [t["value"] for t in j["targets"]],
             "found": sum(len(t.get("results", [])) for t in j["targets"])}
            for j in JOBS.values()]
    return sorted(rows, key=lambda r: r["created"], reverse=True)


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "inconnu")
    return JSONResponse(j)


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str):
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "inconnu")
    j["cancel"] = True
    proc = PROCS.get(job_id)
    if proc and proc.poll() is None:
        stop_tree(proc, force=IS_WIN)
    return {"ok": True}


@app.get("/api/jobs/{job_id}/export.csv")
def export_csv(job_id: str):
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "inconnu")
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["cible", "type", "source", "site", "url", "tags", "infos_publiques"])
    for t in j["targets"]:
        for r in t.get("results", []):
            w.writerow([t["value"], t["kind"], r["source"], r["site"], r["url"],
                        ";".join(r["tags"]), json.dumps(r["infos"], ensure_ascii=False)])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f"attachment; filename=audit_{job_id}.csv"})


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str):
    """Supprime une analyse et ses fichiers (les rapports contiennent des données personnelles agrégées)."""
    if not re.fullmatch(r"[0-9a-f]{12}", job_id):
        raise HTTPException(400, "id invalide")
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "inconnu")
    if j["state"] in ("running", "queued"):
        raise HTTPException(409, "analyse en cours : annule-la d'abord")
    JOBS.pop(job_id, None)
    shutil.rmtree(JOBS_DIR / job_id, ignore_errors=True)
    journal("analyse", f"Analyse du {datetime.fromtimestamp(j['created']).strftime('%d/%m/%Y %H:%M')} supprimée", job_id)
    return {"ok": True}


@app.get("/api/jobs/{job_id}/analysis")
def get_analysis(job_id: str, first: Optional[str] = None, last: Optional[str] = None):
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "inconnu")
    base = j.get("identity") or {}
    ident = clean_ident(base.get("first") if first is None else first,
                        base.get("last") if last is None else last)
    return analyze_job(j, ident)


# ------------------------------------------------------- Suivi des demandes
REQ_FILE = BASE / "demandes.json"
REQ_LOCK = threading.Lock()
RE_ID10 = re.compile(r"^[0-9a-f]{10}$")
RE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
REQ_STATUS = ["à envoyer", "envoyée", "relancée", "réponse reçue", "effacé", "refusée"]
REQ_KIND = ["source", "déréférencement"]
REQ_WAITING = ("envoyée", "relancée")
REQ_ART = ("", "15", "17", "15+17")  # accès, effacement, les deux


def add_months(d, n):
    m = d.month - 1 + n
    y, m = d.year + m // 12, m % 12 + 1
    dim = [31, 29 if (y % 4 == 0 and (y % 100 or y % 400 == 0)) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]
    return date(y, m, min(d.day, dim))


def load_reqs():
    try:
        d = json.loads(REQ_FILE.read_text(encoding="utf-8"))
        return [x for x in d if isinstance(x, dict) and x.get("id")] if isinstance(d, list) else []
    except Exception:  # noqa: BLE001
        return []


def save_reqs(lst):
    tmp = REQ_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(lst, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(REQ_FILE)


def req_view(x, today=None):
    """Ajoute les échéances calculées : 1 mois après l'envoi (art. 12.3), jusqu'à 3 mois si demande complexe."""
    today = today or date.today()
    v = dict(x)
    v["due"] = v["limit"] = None
    v["days_left"] = None
    v["overdue"] = False
    if RE_DATE.match(x.get("sent", "") or ""):
        try:
            sent = date.fromisoformat(x["sent"])
            due, lim = add_months(sent, 1), add_months(sent, 3)
            v["due"], v["limit"] = due.isoformat(), lim.isoformat()
            if x.get("status") in REQ_WAITING:
                v["days_left"] = (due - today).days
                v["overdue"] = today > due
        except ValueError:
            pass
    return v


def clean_req(d, partial=False):
    out = {}
    def txt(k, n):
        if k in d or not partial:
            out[k] = str(d.get(k, "") or "").strip()[:n]
    txt("site", 80); txt("url", 500); txt("ref", 80); txt("note", 500); txt("to", 120)
    if out.get("to") and not RE_MAIL.match(out["to"]):
        raise HTTPException(400, "adresse du destinataire invalide")
    if "art" in d or not partial:
        art = str(d.get("art", "") or "")
        if art not in REQ_ART:
            raise HTTPException(400, "article invalide")
        out["art"] = art
    if "kind" in d or not partial:
        k = d.get("kind", "source")
        if k not in REQ_KIND:
            raise HTTPException(400, "type invalide")
        out["kind"] = k
    if "status" in d or not partial:
        st = d.get("status", "à envoyer")
        if st not in REQ_STATUS:
            raise HTTPException(400, "statut invalide")
        out["status"] = st
    if "sent" in d or not partial:
        sd = str(d.get("sent", "") or "").strip()
        if sd:
            try:
                date.fromisoformat(sd)
            except ValueError:
                raise HTTPException(400, "date invalide (AAAA-MM-JJ)")
            if not RE_DATE.match(sd):
                raise HTTPException(400, "date invalide (AAAA-MM-JJ)")
        out["sent"] = sd
    if out.get("url") and not re.match(r"^https?://", out["url"]):
        raise HTTPException(400, "le lien doit commencer par http:// ou https://")
    if not partial and not out.get("site"):
        raise HTTPException(400, "nom du site obligatoire")
    if "site" in out and not out["site"]:
        raise HTTPException(400, "nom du site obligatoire")
    return out


def _fill_sent(item):
    if item.get("status") in REQ_WAITING and not item.get("sent"):
        item["sent"] = date.today().isoformat()


@app.get("/api/requests")
def get_requests():
    return {"requests": [req_view(x) for x in load_reqs()]}


@app.post("/api/requests")
async def add_request(request: Request):
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "JSON invalide")
    item = clean_req(body)
    item["id"] = uuid.uuid4().hex[:10]
    item["created"] = date.today().isoformat()
    _fill_sent(item)
    with REQ_LOCK:
        lst = load_reqs()
        lst.append(item)
        save_reqs(lst)
    journal("demande", f"Demande ({item['kind']}) créée pour {item['site']} : {item['status']}", item["id"])
    return req_view(item)


@app.put("/api/requests/{rid}")
async def edit_request(rid: str, request: Request):
    if not RE_ID10.match(rid):
        raise HTTPException(400, "id invalide")
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "JSON invalide")
    upd = clean_req(body, partial=True)
    with REQ_LOCK:
        lst = load_reqs()
        for x in lst:
            if x["id"] == rid:
                before = x.get("status")
                x.update(upd)
                _fill_sent(x)
                save_reqs(lst)
                if x.get("status") != before:
                    journal("demande", f"{x.get('site', '?')} : {before} → {x.get('status')}", rid)
                else:
                    journal("demande", f"{x.get('site', '?')} : demande modifiée", rid)
                return req_view(x)
    raise HTTPException(404, "inconnu")


@app.delete("/api/requests/{rid}")
def del_request(rid: str):
    if not RE_ID10.match(rid):
        raise HTTPException(400, "id invalide")
    with REQ_LOCK:
        lst = load_reqs()
        new = [x for x in lst if x["id"] != rid]
        if len(new) == len(lst):
            raise HTTPException(404, "inconnu")
        save_reqs(new)
    gone = next(x for x in lst if x["id"] == rid)
    journal("demande", f"Demande pour {gone.get('site', '?')} supprimée du suivi", rid)
    return {"ok": True}


def _public_host(host):
    """Refuse les adresses locales/privées (évite que l'app serve à sonder ton réseau)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for i in infos:
        ip = ipaddress.ip_address(i[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def check_page(url):
    """Vérifie si une page répond encore. Indice seulement : une page vide sans erreur (soft 404) passe pour « présente »."""
    u = urlparse(url or "")
    if u.scheme not in ("http", "https") or not u.hostname:
        return {"ok": False, "code": None, "error": "lien invalide"}
    if not _public_host(u.hostname):
        return {"ok": False, "code": None, "error": "adresse locale ou injoignable (refusée)"}

    class NoPrivateRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            nu = urlparse(newurl)
            if nu.scheme not in ("http", "https") or not nu.hostname or not _public_host(nu.hostname):
                return None
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(NoPrivateRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (audit-donnees-perso; verification de ma propre page)"})
    try:
        with opener.open(req, timeout=15) as r:
            return {"ok": True, "code": r.status, "final": r.geturl()}
    except urllib.error.HTTPError as e:
        return {"ok": True, "code": e.code, "final": url}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "code": None, "error": str(e)[:160]}


def interpret_check(c):
    code = c.get("code")
    if code is None:
        return "injoignable : " + c.get("error", "?")
    if code in (404, 410):
        return f"HTTP {code} : page introuvable (suppression probable, à confirmer à la main)"
    if 200 <= code < 300:
        return f"HTTP {code} : la page répond encore (elle peut quand même ne plus contenir tes données : ouvre-la)"
    if code in (401, 403, 429):
        return f"HTTP {code} : accès refusé, le site bloque les vérifications automatiques : ouvre la page toi-même"
    return f"HTTP {code} : résultat non concluant, ouvre la page toi-même"


@app.post("/api/requests/{rid}/check")
def check_request(rid: str):
    if not RE_ID10.match(rid):
        raise HTTPException(400, "id invalide")
    lst = load_reqs()
    x = next((r for r in lst if r["id"] == rid), None)
    if not x:
        raise HTTPException(404, "inconnu")
    if not x.get("url"):
        raise HTTPException(400, "aucun lien à vérifier sur cette demande")
    c = check_page(x["url"])
    res = {"at": datetime.now().strftime("%Y-%m-%d %H:%M"), "code": c.get("code"), "text": interpret_check(c)}
    with REQ_LOCK:
        lst = load_reqs()
        for y in lst:
            if y["id"] == rid:
                y["last_check"] = res
                save_reqs(lst)
    journal("demande", f"Vérification de la page {x.get('site', '?')} : {res['text']}", rid)
    return res


# ------------------------------------------------- Comparaison entre analyses
def _result_keys(job, targets):
    out = {}
    for t in job["targets"]:
        if (t["kind"], t["value"]) in targets:
            for r in t.get("results", []):
                out[(t["value"], norm_url(r.get("url", "")))] = {"target": t["value"], "site": r.get("site", "?"),
                                                                   "url": r.get("url", "")}
    return out


def _incomplete(job, targets):
    notes = []
    for t in job["targets"]:
        if (t["kind"], t["value"]) not in targets:
            continue
        w = t.get("warn") or ""
        if t.get("status") != "terminé" or "interrompu" in w:
            notes.append(f"{t['value']} : scan incomplet ou interrompu")
        for tool, c in (("Holehe", t.get("coverage")), ("user-scanner", t.get("coverage_us"))):
            if coverage_degraded(c):
                notes.append(f"{t['value']} : {tool} {degraded_msg(c)}")
    return notes


def compare_jobs(job, prev=None):
    mine = {(t["kind"], t["value"]) for t in job["targets"]}
    if prev is None:
        cands = [j for j in JOBS.values() if j["id"] != job["id"] and j.get("created", 0) < job.get("created", 0)
                 and j.get("state") == "terminé" and mine & {(t["kind"], t["value"]) for t in j["targets"]}]
        if not cands:
            return {"previous": None}
        prev = max(cands, key=lambda j: j["created"])
    common = mine & {(t["kind"], t["value"]) for t in prev["targets"]}
    a, b = _result_keys(prev, common), _result_keys(job, common)
    new = [v for k, v in b.items() if k not in a]
    gone = [v for k, v in a.items() if k not in b]
    caveats = _incomplete(prev, common) + _incomplete(job, common)
    return {"previous": {"id": prev["id"], "created": prev["created"]},
            "common_targets": sorted(v for _, v in common),
            "new": new, "gone": gone, "same": len(set(a) & set(b)),
            "caveats": list(dict.fromkeys(caveats))}


@app.get("/api/jobs/{job_id}/compare")
def get_compare(job_id: str):
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "inconnu")
    return compare_jobs(j)


PWNED_RE = re.compile(r"^[0-9A-Fa-f]{5}$")


@app.get("/api/pwned/range/{prefix}")
def pwned_range(prefix: str):
    """Relais k-anonymat vers Pwned Passwords : reçoit 5 caractères de hash, jamais le mot de passe."""
    from fastapi.responses import PlainTextResponse
    if not PWNED_RE.match(prefix):
        raise HTTPException(400, "préfixe invalide (5 caractères hexadécimaux)")
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix.upper()}",
        headers={"User-Agent": "audit-donnees-perso (usage personnel)", "Add-Padding": "true"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return PlainTextResponse(r.read().decode("utf-8", "replace"))
    except Exception as e:
        raise HTTPException(502, f"Pwned Passwords injoignable : {e}")


LEAKS_FILE = BASE / "leaks.json"
LEAKS_LOCK = threading.Lock()
RE_LEAK_ID = re.compile(r"^[0-9a-f]{10}$")

LEAK_RULES = [  # (mots-clés dans les données exposées, conseil)
    (("bancaire", "iban", "bank", "carte", "card", "paiement", "payment"),
     "Données bancaires : surveille tes prélèvements, active les alertes de ta banque, méfie-toi des faux appels « banque »."),
    (("mot de passe", "password", "hash", "jeton", "token", "authentification"),
     "Accès exposés : change le mot de passe de ce service (et partout où tu l'as réutilisé) ; retire les applications connectées."),
    (("naissance", "birth", "adresse postale", "physical address", "téléphone", "phone", "civilité", "état civil", "geographic"),
     "Identité / coordonnées : attends-toi à de l'hameçonnage ciblé (SMS, appels, courriers) qui cite ces informations."),
    (("e-mail", "email", "adresse e-m"),
     "Adresse email exposée : le spam et le phishing sont probables ; ne clique pas sur les liens des messages inattendus."),
]


def leak_advice(data):
    d = (data or "").lower()
    out = [adv for kws, adv in LEAK_RULES if any(k in d for k in kws)]
    out.append("Pour savoir ce que ce service détient sur toi : demande RGPD d'accès (art. 15) ; "
               "si tu n'utilises plus le compte : suppression (art. 17).")
    return out


def load_leaks():
    try:
        d = json.loads(LEAKS_FILE.read_text(encoding="utf-8"))
        return [x for x in d if isinstance(x, dict) and x.get("id")] if isinstance(d, list) else []
    except Exception:  # noqa: BLE001
        return []


def save_leaks(lst):
    tmp = LEAKS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(lst, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(LEAKS_FILE)


class LeakBody(BaseModel):
    address: str = ""
    service: str
    date: str = ""
    data: str = ""


@app.get("/api/leaks")
def get_leaks():
    return {"leaks": [dict(x, advice=leak_advice(x.get("data", ""))) for x in load_leaks()]}


@app.post("/api/leaks")
def add_leak(body: LeakBody):
    svc = body.service.strip()[:80]
    if not svc:
        raise HTTPException(400, "nom du service obligatoire")
    item = {"id": uuid.uuid4().hex[:10], "address": body.address.strip()[:120], "service": svc,
            "date": body.date.strip()[:20], "data": body.data.strip()[:400]}
    with LEAKS_LOCK:
        lst = load_leaks()
        lst.append(item)
        save_leaks(lst)
    journal("fuite", f"Fuite notée : {svc}" + (f" ({item['date']})" if item["date"] else ""), item["id"])
    return dict(item, advice=leak_advice(item["data"]))


@app.delete("/api/leaks/{leak_id}")
def del_leak(leak_id: str):
    if not RE_LEAK_ID.match(leak_id):
        raise HTTPException(400, "id invalide")
    with LEAKS_LOCK:
        lst = load_leaks()
        new = [x for x in lst if x.get("id") != leak_id]
        if len(new) == len(lst):
            raise HTTPException(404, "inconnu")
        save_leaks(new)
    gone = next(x for x in lst if x.get("id") == leak_id)
    journal("fuite", f"Fuite retirée de la liste : {gone.get('service', '?')}", leak_id)
    return {"ok": True}


@app.get("/api/checklist")
def get_checklist():
    return {"done": load_checks()}


@app.put("/api/checklist")
def put_checklist(body: CheckBody):
    if not RE_CHECK_ID.match(body.id):
        raise HTTPException(400, "id invalide")
    with CHECK_LOCK:
        d = load_checks()
        changed = bool(d.get(body.id)) != bool(body.done)
        d[body.id] = body.done
        tmp = CHECKLIST_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(CHECKLIST_FILE)
    if changed:
        journal("checklist", f"Contrôle « {(body.label.strip()[:120] or body.id)} » {'coché' if body.done else 'décoché'}")
    return {"done": d}


DATA_FILES = ("jobs", "leaks.json", "demandes.json", "checklist.json", "config.json", "rapports_hebdo", "journal.jsonl")


def has_data(d):
    return any((d / n).exists() for n in DATA_FILES if n != "jobs") or any((d / "jobs").glob("*/job.json"))


@app.get("/api/settings")
def get_settings():
    saved = load_settings().get("data_dir") or ""
    return {"data_dir": str(BASE), "source": DATA_SOURCE, "default": str(DEFAULT_BASE),
            "saved": saved, "settings_file": str(SETTINGS_FILE)}


UI_DEFAULT = {"layout": "console", "theme": "system", "tiles": {"order": [], "hidden": []}}
RE_TILE = re.compile(r"^[a-z]{2,20}$")


def ui_settings():
    u = load_settings().get("ui")
    out = json.loads(json.dumps(UI_DEFAULT))
    if isinstance(u, dict):
        if u.get("layout") in ("console", "menu"):
            out["layout"] = u["layout"]
        if u.get("theme") in ("system", "dark", "light"):
            out["theme"] = u["theme"]
        t = u.get("tiles") if isinstance(u.get("tiles"), dict) else {}
        for k in ("order", "hidden"):
            if isinstance(t.get(k), list):
                out["tiles"][k] = [x for x in t[k] if isinstance(x, str) and RE_TILE.match(x)][:30]
    return out


@app.get("/api/settings/ui")
def get_ui():
    return ui_settings()


@app.put("/api/settings/ui")
async def put_ui(request: Request):
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "JSON invalide")
    st = load_settings()
    st["ui"] = dict(ui_settings(), **{k: v for k, v in body.items() if k in UI_DEFAULT})
    save_settings(st)
    st["ui"] = ui_settings()  # nettoie ce qui vient d'être fusionné
    save_settings(st)
    return st["ui"]


@app.get("/api/status")
def tools_status():
    """Disponibilité et version des outils embarqués (pour la tuile « Outils »)."""
    import importlib.metadata as md
    import importlib.util
    out = []
    for name, mod, dist in (("Maigret", "maigret", "maigret"), ("Sherlock", "sherlock_project", "sherlock-project"),
                            ("Holehe", "holehe", "holehe"), ("user-scanner", "user_scanner", "user-scanner")):
        ok = importlib.util.find_spec(mod) is not None
        try:
            ver = md.version(dist)
        except Exception:  # noqa: BLE001
            ver = ""
        out.append({"name": name, "ok": ok, "version": ver})
    return {"tools": out, "ollama_url": OLLAMA_URL}


class DataDirBody(BaseModel):
    path: str = ""        # vide = revenir au défaut (~/osint)
    copy_data: bool = False


@app.post("/api/settings/data-dir")
def set_data_dir(body: DataDirBody):
    raw = body.path.strip()
    if not raw:
        target = DEFAULT_BASE
    else:
        target = Path(raw).expanduser()
        if not target.is_absolute():
            raise HTTPException(400, "indique un chemin complet, par ex. /home/moi/osint-donnees ou ~/osint-donnees")
        target = target.resolve()
    if target.exists() and not target.is_dir():
        raise HTTPException(400, "ce chemin est un fichier, pas un dossier")
    if target == BASE.resolve():
        raise HTTPException(400, "c'est déjà le dossier utilisé")
    if BASE.resolve() in target.parents:
        raise HTTPException(400, "le nouveau dossier ne peut pas être à l'intérieur de l'actuel")
    if any(j.get("state") in ("running", "queued") for j in JOBS.values()):
        raise HTTPException(409, "une analyse est en cours : attends la fin")
    try:
        target.mkdir(parents=True, exist_ok=True)
        safe_chmod(target, 0o700)
        probe = target / ".audit-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as e:
        raise HTTPException(400, f"dossier inutilisable : {e.strerror or e}") from e
    copied = []
    if body.copy_data:
        if has_data(target):
            raise HTTPException(409, "le dossier cible contient déjà des données : copie refusée (rien n'a été écrasé)")
        for n in DATA_FILES:
            src = BASE / n
            if src.is_dir():
                shutil.copytree(src, target / n, dirs_exist_ok=True)
                copied.append(n)
            elif src.is_file():
                shutil.copy2(src, target / n)
                copied.append(n)
    st = load_settings()
    if raw:
        st["data_dir"] = str(target)
    else:
        st.pop("data_dir", None)
    save_settings(st)
    journal("réglage", f"Dossier de données changé pour {target}" + (" (données copiées)" if copied else "")
            + " : actif au prochain démarrage")
    note = ""
    if DATA_SOURCE in ("cli", "env"):
        note = ("Attention : l'option --data-dir ou la variable OSINT_DATA_DIR est active et reste prioritaire "
                "sur ce réglage tant qu'elle est utilisée.")
    return {"ok": True, "data_dir": str(target), "copied": copied, "restart": True, "note": note}


@app.post("/api/leaks/import")
async def import_leaks(request: Request):
    """Fusionne une liste exportée (leaks.json) : ajoute seulement les fuites absentes, ne supprime rien."""
    body = await request.json()
    items = body.get("leaks") if isinstance(body, dict) else body
    if not isinstance(items, list):
        raise HTTPException(400, "liste de fuites attendue (fichier leaks.json exporté)")
    if len(items) > 2000:
        raise HTTPException(400, "fichier trop gros (2000 fuites maximum)")
    key = lambda x: (x.get("service", "").strip().lower(), x.get("date", "").strip().lower(),  # noqa: E731
                     x.get("address", "").strip().lower())
    added, skipped = [], 0
    with LEAKS_LOCK:
        lst = load_leaks()
        have = {key(x) for x in lst}
        for x in items:
            if not isinstance(x, dict) or not str(x.get("service", "")).strip():
                skipped += 1
                continue
            it = {"id": uuid.uuid4().hex[:10], "address": str(x.get("address", "")).strip()[:120],
                  "service": str(x["service"]).strip()[:80], "date": str(x.get("date", "")).strip()[:20],
                  "data": str(x.get("data", "")).strip()[:400]}
            if key(it) in have:
                skipped += 1
                continue
            have.add(key(it))
            lst.append(it)
            added.append(it)
        if added:
            save_leaks(lst)
    journal("fuite", f"Import de fuites : {len(added)} ajoutée(s), {skipped} ignorée(s) (déjà présentes ou invalides)")
    return {"added": len(added), "skipped": skipped}


@app.get("/api/leaks/export")
def export_leaks():
    """Télécharge leaks.json (même format que le fichier, sans les conseils calculés)."""
    lst = load_leaks()
    data = json.dumps(lst, ensure_ascii=False, indent=1)
    journal("fuite", f"Export de leaks.json ({len(lst)} fuite(s))")
    return PlainTextResponse(data, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="leaks-{date.today().isoformat()}.json"'})


def rebuild_journal():
    """Premier lancement avec journal : reconstitue les événements datables à partir des données existantes."""
    if JOURNAL_FILE.exists():
        return 0
    evs = []
    for j in JOBS.values():
        if j.get("created"):
            evs.append((datetime.fromtimestamp(j["created"]), "analyse", f"Analyse lancée : {targets_label(j)}", j["id"]))
        if j.get("finished"):
            found = sum(len(t.get("results", [])) for t in j["targets"])
            evs.append((datetime.fromtimestamp(j["finished"]), "analyse",
                        f"Analyse {STATE_FR.get(j.get('state'), j.get('state', '?'))} : {found} compte(s) trouvé(s)", j["id"]))
    for r in load_reqs():
        for k, txt in (("created", f"Demande ({r.get('kind', '?')}) créée pour {r.get('site', '?')}"),
                       ("sent", f"Demande envoyée à {r.get('site', '?')}")):
            if RE_DATE.match(r.get(k, "") or ""):
                evs.append((datetime.fromisoformat(r[k]), "demande", txt, r["id"]))
        lc = r.get("last_check") or {}
        if lc.get("at"):
            try:
                evs.append((datetime.strptime(lc["at"], "%Y-%m-%d %H:%M"), "demande",
                            f"Vérification de la page {r.get('site', '?')} : {lc.get('text', '')}", r["id"]))
            except ValueError:
                pass
    for f in sorted((REPORT_DIR.glob("*.md") if REPORT_DIR.exists() else [])):
        try:
            evs.append((datetime.fromisoformat(f.stem), "rapport", f"Relance hebdomadaire (rapport {f.name})", None))
        except ValueError:
            pass
    for at, kind, txt, ref in sorted(evs, key=lambda e: e[0]):
        journal(kind, txt, ref, at=at.isoformat(timespec="seconds"), rebuilt=True)
    journal("réglage", f"Journal créé ({len(evs)} événement(s) reconstitué(s) à partir des données existantes)")
    return len(evs)


@app.get("/api/journal")
def get_journal(type: str = "", limit: int = 300):
    evs = read_journal()
    if type:
        if type not in JOURNAL_TYPES:
            raise HTTPException(400, "type inconnu")
        evs = [e for e in evs if e["type"] == type]
    evs.sort(key=lambda e: e["at"], reverse=True)
    return {"events": evs[:max(1, min(limit, 5000))], "total": len(evs), "types": list(JOURNAL_TYPES)}


@app.get("/api/journal/export.csv")
def export_journal():
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["date", "type", "evenement", "reference", "reconstitue"])
    for e in sorted(read_journal(), key=lambda e: e["at"]):
        w.writerow([e["at"].replace("T", " "), e["type"], e["text"], e.get("ref", ""), "oui" if e.get("rebuilt") else ""])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="journal-{date.today().isoformat()}.csv"'})


@app.get("/api/assistant/models")
def assistant_models():
    try:
        d = ollama_call("/api/tags", None, 8)
        return {"ok": True, "url": OLLAMA_URL, "models": sorted(m["name"] for m in d.get("models", []))}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "url": OLLAMA_URL, "error": f"{type(e).__name__}: {e}"}


class OllamaBody(BaseModel):
    url: str = ""  # vide = revenir au défaut (http://127.0.0.1:11434)


@app.post("/api/settings/ollama")
def set_ollama(body: OllamaBody):
    """Enregistre l'adresse d'Ollama dans config.json, l'applique tout de suite et teste la connexion."""
    global OLLAMA_URL
    raw = body.url.strip().rstrip("/")
    if raw:
        try:
            u = urlparse(raw)
            u.port  # lève ValueError si le port est invalide
            ok = u.scheme in ("http", "https") and bool(u.hostname)
        except ValueError:
            ok = False
        if not ok:
            raise HTTPException(400, "adresse invalide : indique par ex. http://192.168.1.169:11434")
    cfg = load_config()
    if raw:
        cfg["ollama_url"] = raw
    else:
        cfg.pop("ollama_url", None)
    tmp = BASE / "config.json.tmp"
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(BASE / "config.json")
    OLLAMA_URL = ollama_url()
    journal("réglage", f"Adresse Ollama : {OLLAMA_URL}")
    out = assistant_models()
    if os.environ.get("OLLAMA_URL"):
        out["note"] = "La variable OLLAMA_URL est définie : elle reste prioritaire sur ce réglage."
    return out


@app.post("/api/jobs/{job_id}/assistant")
def assistant(job_id: str, body: AskBody):
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "inconnu")
    if not re.match(r"^[\w.:\-/]{1,100}$", body.model):
        raise HTTPException(400, "nom de modèle invalide")
    question = body.question.strip()[:2000]
    if not question:
        raise HTTPException(400, "question vide")
    base = j.get("identity") or {}
    ident = clean_ident(body.first or base.get("first"), body.last or base.get("last"))
    analysis = analyze_job(j, ident)
    who = (ident["first"] + " " + ident["last"]).strip() or "l'utilisateur"
    system = (
        f"Tu aides {who} à comprendre le résultat d'un audit de ses PROPRES données diffusées en ligne. "
        "Réponds en français, de façon claire, courte et prudente. Appuie-toi UNIQUEMENT sur les données ci-dessous ; "
        "si une information manque, dis-le au lieu d'inventer. Un pseudo trouvé ne prouve pas que le compte appartient "
        "à la personne. Ne donne pas d'avis juridique ferme. Ne propose jamais de rechercher d'autres personnes.\n\n"
        "RÉSULTATS DE L'AUDIT :\n" + assistant_context(analysis))
    msgs = [{"role": "system", "content": system}]
    for m in (body.history or [])[-6:]:
        if isinstance(m, dict) and m.get("role") in ("user", "assistant") and isinstance(m.get("content"), str):
            msgs.append({"role": m["role"], "content": m["content"][:2000]})
    msgs.append({"role": "user", "content": question})
    try:
        out = ollama_call("/api/chat", {"model": body.model, "messages": msgs, "stream": False, "think": False})
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Ollama injoignable ({OLLAMA_URL}) : {type(e).__name__}: {e}")
    text = RE_THINK.sub("", (out.get("message") or {}).get("content", "")).strip()
    return {"answer": text or "(réponse vide)"}


@app.get("/", response_class=HTMLResponse)
def index():
    return HTML


@app.get("/favicon.png")
def favicon():
    return Response(content=ICON_PNG, media_type="image/png", headers={"Cache-Control": "max-age=86400"})


# ------------------------------------------------------------------------ UI
HTML = r"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit données perso</title>
<link rel="icon" type="image/png" href="/favicon.png">
<style>
/* Disposition « console » (accueil en tuiles) ou « menu » (rubriques groupées) ; thème système / sombre / clair. */
:root{--bg:#eef1f6;--side:#ffffff;--card:#ffffff;--card2:#f5f7fb;--line:#dde2ec;--fg:#1b2230;--mut:#5d6779;
 --acc:#3f5bd8;--accfg:#ffffff;--acc-soft:#e6ebff;--top:#3f5bd8;--topfg:#ffffff;
 --ok:#1f8a5b;--ok-soft:#e1f4ea;--warn:#b26a00;--warn-soft:#fff1d9;--ko:#c23b3b;--ko-soft:#fde5e5;--chipfg:#0f1a12;
 --f:system-ui,-apple-system,"Segoe UI",Ubuntu,Cantarell,sans-serif;--mono:ui-monospace,"DejaVu Sans Mono",monospace;color-scheme:light}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#1e222b;--side:#252a35;--card:#2c3240;--card2:#252a35;--line:#3a4152;--fg:#e4e8f0;--mut:#9aa3b5;
 --acc:#7d93ff;--accfg:#0e1220;--acc-soft:#2f3a66;--top:#4f6df5;--topfg:#ffffff;--ok:#3fbf7f;--ok-soft:#173a2b;--warn:#e9a23b;--warn-soft:#3a2c14;--ko:#e5605f;--ko-soft:#3d1d22;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#1e222b;--side:#252a35;--card:#2c3240;--card2:#252a35;--line:#3a4152;--fg:#e4e8f0;--mut:#9aa3b5;
 --acc:#7d93ff;--accfg:#0e1220;--acc-soft:#2f3a66;--top:#4f6df5;--topfg:#ffffff;--ok:#3fbf7f;--ok-soft:#173a2b;--warn:#e9a23b;--warn-soft:#3a2c14;--ko:#e5605f;--ko-soft:#3d1d22;color-scheme:dark}
*{box-sizing:border-box}[hidden]{display:none!important}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:14.5px/1.45 var(--f);display:flex;flex-direction:column}
a{color:var(--acc)}
/* barre du haut */
.top{display:flex;align-items:center;gap:10px;padding:8px 14px;background:var(--top);color:var(--topfg);flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:8px;font-weight:700;font-size:15.5px}.brand svg{width:26px;height:26px}
.top .sp{flex:1}
.top .lbl{font-size:12.5px;opacity:.9}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:7px;overflow:hidden}
.seg button{border:0;border-radius:0;background:transparent;color:inherit;padding:4px 10px;font-size:12.5px}
.seg button[aria-pressed="true"]{background:var(--acc);color:var(--accfg)}
.top .seg{border-color:rgba(255,255,255,.4)}.top .seg button{color:var(--topfg)}
.top .seg button[aria-pressed="true"]{background:rgba(255,255,255,.95);color:#1b2230}
.top .go{background:rgba(255,255,255,.95);color:#1b2230;border-color:transparent;font-weight:600}
/* coque */
.shell{flex:1;display:grid;grid-template-columns:210px minmax(0,1fr) 320px;min-height:0}
nav.side{background:var(--side);border-right:1px solid var(--line);padding:10px 0;display:flex;flex-direction:column;overflow:auto}
nav.side .who{padding:4px 16px 10px;border-bottom:1px solid var(--line);margin-bottom:6px;font-size:12px;color:var(--mut)}
nav.side .grp{font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);padding:12px 16px 4px}
nav.side button{all:unset;cursor:pointer;display:flex;align-items:center;gap:10px;padding:8px 16px;font-size:13.5px;border-left:3px solid transparent}
nav.side button:hover{background:var(--card2)}
nav.side button[aria-current="true"]{border-left-color:var(--acc);color:var(--acc);background:var(--card2);font-weight:600}
nav.side button:focus-visible{outline:2px solid var(--acc);outline-offset:-2px}
nav.side .cnt{margin-left:auto}
.ico{width:16px;height:16px;flex:none;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
main{padding:14px;overflow:auto;min-width:0;display:flex;flex-direction:column;gap:12px}
aside.rail{border-left:1px solid var(--line);padding:14px;overflow:auto;display:flex;flex-direction:column;gap:12px;background:var(--card2)}
.crumb{font-size:12.5px;color:var(--mut)}
.view{display:flex;flex-direction:column;gap:12px}
@media(max-width:1180px){html,body{height:auto}main,aside.rail{overflow:visible}.shell{grid-template-columns:200px minmax(0,1fr)}aside.rail{grid-column:1/-1;border-left:0;border-top:1px solid var(--line)}}
@media(max-width:720px){.shell{grid-template-columns:minmax(0,1fr)}nav.side{flex-direction:row;border-right:0;border-bottom:1px solid var(--line);overflow-x:auto}nav.side .who,nav.side .grp{display:none}nav.side button{border-left:0;border-bottom:3px solid transparent;white-space:nowrap}nav.side button[aria-current="true"]{border-bottom-color:var(--acc)}}
/* cartes et contrôles */
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;min-width:0}
details.card{padding:0}details.card>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:8px;padding:11px 14px;font-weight:600}
details.card>summary::-webkit-details-marker{display:none}
details.card>summary::after{content:"▾";margin-left:auto;color:var(--mut)}details.card:not([open])>summary::after{content:"▸"}
details.card[open]>summary{border-bottom:1px solid var(--line)}details.card>.in{padding:12px 14px}
h2{font-size:15.5px;margin:0 0 10px;font-weight:600}h3{font-size:14px;margin:14px 0 6px}
input[type=text],input[type=number],input[type=email],input[type=password],input[type=date],textarea,select{padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--card2);color:var(--fg);font:inherit;font-size:13.5px;min-width:0}
input[type=text],input[type=email],textarea{width:100%}
.row{display:flex;gap:6px;margin-bottom:6px;align-items:center;flex-wrap:wrap}.row>input[type=text]{flex:1}
button,.btn{padding:6px 12px;border:1px solid var(--line);border-radius:6px;background:var(--card2);color:var(--fg);cursor:pointer;font:inherit;font-size:13.5px;text-decoration:none;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
button:hover,.btn:hover{border-color:var(--acc)}
button.pri,.btn.pri{background:var(--acc);color:var(--accfg);border-color:var(--acc);font-weight:600}button:disabled{opacity:.5;cursor:default}
button:focus-visible,.btn:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,summary:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
label{display:block;margin:6px 0}small,.mut{color:var(--mut)}
.bar{height:8px;background:var(--line);border-radius:6px;overflow:hidden}.bar>i{display:block;height:100%;background:var(--acc);width:0;transition:width .4s}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;border:1px solid var(--line)}
.p-ok{background:var(--ok-soft);color:var(--ok);border-color:transparent}.p-warn{background:var(--warn-soft);color:var(--warn);border-color:transparent}.p-ko{background:var(--ko-soft);color:var(--ko);border-color:transparent}
.s-terminé{color:var(--ok)}.s-erreur{color:var(--ko)}.s-en\ cours{color:var(--acc)}.s-annulé,.s-interrompu{color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}.tscroll{overflow-x:auto}
pre{background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:8px;max-height:200px;overflow:auto;font-size:12px;margin:8px 0 0;white-space:pre-wrap}
.kv{font-size:12.5px;color:var(--mut)}.kv b{color:var(--fg);font-weight:600}
.hist div{padding:6px 0;border-bottom:1px solid var(--line);cursor:pointer;font-size:13px}.hist div:hover{color:var(--acc)}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-bottom:12px}
@media(max-width:700px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
.kpi{background:var(--card2);border:1px solid var(--line);border-radius:8px;padding:10px;text-align:center}
.kpi b{display:block;font-size:24px;font-variant-numeric:tabular-nums}.kpi span{font-size:12px;color:var(--mut)}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-bottom:8px}
.hb{display:grid;grid-template-columns:120px 1fr 28px;gap:6px;align-items:center;font-size:12.5px;margin:3px 0}
.hbar{height:9px;background:var(--line);border-radius:5px;overflow:hidden}.hbar i{display:block;height:100%;background:var(--acc)}
.ai{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0;background:var(--card2)}
.ai.prio{border-left-color:var(--ko)}.ai.verif{border-left-color:var(--warn)}.ai.faible{border-left-color:var(--ok)}
.ai p{margin:6px 0;font-size:13.5px}
.badge{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:9px;border:1px solid var(--line);margin:0 4px 4px 0;color:var(--mut)}
.badge.hot{color:var(--ko);border-color:var(--ko)}
.chat .u,.chat .a{padding:8px 10px;border-radius:8px;margin:6px 0;white-space:pre-wrap;font-size:13.5px}
.chat .u{background:var(--acc-soft)}.chat .a{background:var(--card2);border:1px solid var(--line)}
details summary{cursor:pointer;color:var(--mut);margin:8px 0}
.ck label{display:flex;gap:8px;align-items:flex-start;margin:6px 0;font-size:13.5px}.ck input{margin-top:3px}
.ck label.dn span{text-decoration:line-through;color:var(--mut)}
.err{color:var(--ko);margin:6px 0 0;font-size:13px}
.degraded{background:var(--ko-soft);color:var(--ko);border:2px solid var(--ko);border-radius:10px;padding:10px 12px;margin:8px 0}
.flash{animation:fl 1.6s ease-out}@keyframes fl{from{box-shadow:0 0 0 3px var(--acc)}to{box-shadow:0 0 0 0 transparent}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
/* tuiles de la console */
.dashbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:12px;align-items:start}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;min-width:0}
.tile>.h{display:flex;align-items:center;gap:8px;padding:10px 14px 4px}
.tile>.h h3{margin:0;font-size:15px;font-weight:500}
.tile>.h .lnk{margin-left:auto;font-size:12px;padding:2px 8px}
.tile>.c{padding:8px 14px 14px;display:flex;flex-direction:column;gap:10px}
.tile .tools{display:none;margin-left:auto;gap:4px}
.editing .tile{cursor:grab;border-style:dashed}.editing .tile .tools{display:inline-flex}.editing .tile .lnk{display:none}
.editing .tile.off{opacity:.45}.tile.drag{opacity:.4}.tile.over{outline:2px solid var(--acc)}
.tile .tools button{padding:2px 7px;font-size:12px}
.big{font-size:32px;font-weight:700;font-variant-numeric:tabular-nums;line-height:1}
.chips{display:grid;grid-template-columns:repeat(auto-fill,minmax(112px,1fr));gap:6px}
.chip{all:unset;cursor:pointer;border-radius:4px;padding:7px 9px;font-size:12.5px;line-height:1.3;color:var(--chipfg)}
.chip b{display:block;font-size:13px}.chip:focus-visible{outline:2px solid var(--fg)}
.c-ok{background:var(--ok)}.c-warn{background:var(--warn)}.c-ko{background:var(--ko);color:#fff}.c-off{background:var(--card2);color:var(--mut);border:1px solid var(--line)}
.dl{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:13px;margin:0}.dl dt{color:var(--mut)}.dl dd{margin:0}
.donut{display:flex;align-items:center;gap:16px;flex-wrap:wrap}.legend{display:flex;flex-direction:column;gap:4px;font-size:13px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
.ev{display:flex;gap:10px;padding:6px 0;border-top:1px solid var(--line);font-size:13px;align-items:flex-start;flex-wrap:wrap}.ev .pill{flex:none}.ev .t{white-space:nowrap;color:var(--mut);font-variant-numeric:tabular-nums}
/* fenêtre de mail */
dialog{border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--fg);width:min(740px,94vw);padding:0}
dialog::backdrop{background:rgba(10,14,22,.5)}
dialog .hd{display:flex;align-items:center;gap:8px;padding:12px 16px;border-bottom:1px solid var(--line)}
dialog .bd{padding:12px 16px;display:flex;flex-direction:column;gap:8px}
dialog .ft{padding:12px 16px;border-top:1px solid var(--line);display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
dialog textarea{height:300px;font-family:var(--mono);font-size:12.5px}
dialog label{margin:0;font-size:12.5px;color:var(--mut)}
</style></head><body>
<div class="top">
  <span class="brand"><svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" fill="#1b2230"/><path d="M32 8l18 6v14c0 12-8 21-18 26C22 49 14 40 14 28V14z" fill="#6d8bff"/><circle cx="29" cy="29" r="8" fill="none" stroke="#fff" stroke-width="3"/><path d="M35 35l9 9" stroke="#fff" stroke-width="4" stroke-linecap="round"/></svg>Audit données perso</span>
  <span class="sp"></span>
  <span class="lbl">Disposition</span><div class="seg" role="group" aria-label="Disposition"><button id="lyconsole" data-layout="console">Console</button><button id="lymenu" data-layout="menu">Menu</button></div>
  <div class="seg" role="group" aria-label="Thème"><button id="thsystem" data-theme-set="system" title="Suivre le système">Auto</button><button id="thdark" data-theme-set="dark">Sombre</button><button id="thlight" data-theme-set="light">Clair</button></div>
  <button class="go" id="topgo" data-go="scan">+ Nouvelle analyse</button>
</div>
<div class="shell">
<nav class="side" id="side" aria-label="Rubriques"></nav>
<main>
 <div class="crumb" id="crumb"></div>

 <section class="view" data-view="dash" hidden>
  <div class="dashbar"><h2 style="margin:0">Tableau de bord</h2><span class="sp" style="flex:1"></span><span id="dashhint" class="mut" style="font-size:12.5px" hidden>Glisse les tuiles pour les déplacer, ou utilise ← →. « Masquer » retire une tuile de l'accueil.</span><button id="dashreset" hidden>Réinitialiser</button><button id="dashedit">Personnaliser</button></div>
  <div class="tiles" id="tiles"></div>
 </section>

 <section class="view" data-view="scan" hidden>
  <div class="card">
    <h2>Qui suis-je ? <small>(optionnel, reste local)</small></h2>
    <div class="row"><input type="text" id="idfirst" placeholder="Prénom" oninput="idChanged()"><input type="text" id="idlast" placeholder="Nom" oninput="idChanged()"></div>
    <small>Sert à estimer si un profil trouvé est le tien (comparaison avec le nom affiché sur le profil), à pré-remplir les mails et la recherche par nom.</small>
  </div>
  <div class="card">
    <h2>Pseudos</h2><div id="pseudos"></div>
    <button onclick="addField('pseudos','pseudo')">+ pseudo</button>
    <h2 style="margin-top:14px">Adresses email</h2><div id="emails"></div>
    <button onclick="addField('emails','email@exemple.fr')">+ email</button>
  </div>
  <details class="card"><summary>Options Maigret et Sherlock</summary><div class="in">
    <label><input type="checkbox" id="allsites"> Tous les sites (long, plusieurs milliers)</label>
    <label>Top sites : <input type="number" id="top" value="500" min="50" max="3000" style="width:90px"></label>
    <label>Timeout par site (s) : <input type="number" id="timeout" value="20" min="5" max="120" style="width:90px"></label>
    <label>Durée max par outil (min) : <input type="number" id="maxmin" value="20" min="2" max="180" style="width:90px"></label>
    <label><input type="checkbox" id="sherlock" checked> Ajouter Sherlock (pseudos, ~400 sites, doublons fusionnés)</label>
    <label><input type="checkbox" id="nsfw"> Inclure les sites adultes (Sherlock, user-scanner)</label>
    <label><input type="checkbox" id="userscanner"> Essai : ajouter user-scanner pour les emails (~170 sites ; ceux qui t'enverraient un e-mail ne sont jamais testés)</label>
    <small>Variantes : <b>franck{?}dupont</b> teste franck_dupont, franck-dupont, franck.dupont (Sherlock seul, sans Maigret).<br>
    Holehe : sites où l'email a un compte (méthode "mot de passe oublié").</small>
  </div></details>
  <button class="pri" id="go" onclick="start()" style="justify-content:center;padding:10px">Lancer l'analyse</button>
  <p class="err" id="goerr"></p>
  <p><small>Uniquement tes propres identifiants.</small></p>
 </section>

 <section class="view" data-view="res" hidden>
  <div id="empty" class="card mut">Aucune analyse affichée. Lance-en une (« + Nouvelle analyse ») ou choisis-en une dans l'historique.</div>
  <div id="view" style="display:none;flex-direction:column;gap:12px">
    <div class="card">
      <h2>Suivi <span id="state" class="pill"></span></h2>
      <div class="bar"><i id="pbar"></i></div>
      <p class="mut" id="ptxt"></p>
      <div id="tlist"></div>
      <div class="row"><button id="cancel" onclick="cancelJob()">Annuler</button>
        <a id="csv" href="#" class="btn">Export CSV</a>
        <a id="json" href="#" target="_blank" class="btn">JSON brut</a>
        <button id="del" onclick="delJob()">Supprimer</button></div>
      <details><summary>Journal de l'outil</summary><pre id="log"></pre></details>
    </div>
    <div id="an" style="display:none;flex-direction:column;gap:12px">
      <div class="card"><h2>Analyse <small>— comprendre ce qui a été trouvé</small></h2>
        <div class="kpis" id="kpis"></div>
        <div class="charts">
          <div><h3>Par catégorie</h3><div id="ch_cat"></div></div>
          <div><h3>Ce profil est-il à moi ?</h3><div id="ch_match"></div></div>
          <div><h3>Données visibles publiquement</h3><div id="ch_fields"></div></div>
        </div>
        <h3>Plan d'action</h3><ol id="plan"></ol>
        <div id="cmp"></div>
        <p class="mut" style="font-size:12.5px">« Correspondance » = comparaison entre ton prénom/nom et le nom affiché sur le profil. C'est une estimation, pas une preuve : vérifie toujours la page.</p>
      </div>
      <div class="card"><h2>Comptes, du plus important au moins important</h2><div id="anitems"></div></div>
    </div>
    <details class="card"><summary>Rapport site par site</summary><div class="in">
      <input type="text" id="filter" placeholder="Filtrer (site, cible, info…)" oninput="renderResults()">
      <p class="mut" style="font-size:13px">Ce qui est affiché = ce qui est <b>détectable de l'extérieur</b> (compte existant, infos de profil publiques). Ce que chaque site détient en interne ne se voit pas d'ici : « Faire une demande » prépare un mail d'accès (art. 15) ou d'effacement (art. 17).</p>
      <div id="results" class="tscroll"></div>
    </div></details>
  </div>
 </section>

 <section class="view" data-view="req" hidden>
  <div class="card" id="rq"><h2>Demandes <small>— effacement / accès (RGPD), échéances, relances</small></h2>
     <div id="rqlist"></div>
     <details><summary>Ajouter une demande à la main</summary>
     <div class="row"><input type="text" id="rqsite" placeholder="site / organisme" style="flex:1;min-width:160px"><input type="text" id="rqurl" placeholder="lien de la page concernée (https://…)" style="flex:2;min-width:220px"></div>
     <div class="row"><select id="rqkind" title="Suppression à la source ou déréférencement d'un moteur de recherche"><option>source</option><option>déréférencement</option></select><select id="rqstatus"><option>à envoyer</option><option>envoyée</option><option>relancée</option><option>réponse reçue</option><option>effacé</option><option>refusée</option></select><input type="date" id="rqsent" title="Date d'envoi"><input type="text" id="rqref" placeholder="n° de dossier" style="flex:1;min-width:110px"><input type="text" id="rqnote" placeholder="note" style="flex:2;min-width:140px"><button id="rqadd">Ajouter</button></div>
     </details>
     <p id="rqerr" class="err"></p>
     <p class="mut" style="font-size:12px"><b>Source</b> = la page est supprimée chez l'éditeur ; <b>déréférencement</b> = le résultat disparaît d'un moteur de recherche, la page existe toujours. Échéance : 1 mois après l'envoi (art. 12.3 du RGPD), jusqu'à 3 mois si la demande est complexe. L'application n'envoie rien : ta messagerie s'ouvre avec le texte et c'est toi qui envoies. Garde les accusés de réception et numéros de dossier.</p>
  </div>
 </section>

 <section class="view" data-view="leak" hidden>
  <div class="card" id="lk"><h2>Fuites connues <small>— à noter à la main (ex. compte gratuit haveibeenpwned.com)</small></h2>
     <div class="row"><a id="lkexp" class="btn" href="/api/leaks/export" download>Exporter (leaks.json)</a><button id="lkimpbtn">Importer un export…</button><input type="file" id="lkfile" accept=".json,application/json" hidden></div>
     <div id="lkimp" class="card" style="background:var(--card2)" hidden></div>
     <div class="row"><input type="text" id="lkaddr" placeholder="adresse email concernée" style="flex:2;min-width:180px"><input type="text" id="lksvc" placeholder="service / site (ex. Bouygues Télécom)" style="flex:2;min-width:180px"><input type="text" id="lkdate" placeholder="date (ex. août 2025)" style="flex:1;min-width:120px"></div>
     <div class="row"><input type="text" id="lkdata" placeholder="données exposées, copiées depuis « Détails » (ex. numéros de compte bancaire, dates de naissance)" style="flex:1"><button id="lkadd">Ajouter</button></div>
     <p id="lkerr" class="err"></p>
     <div id="lklist"></div>
     <p class="mut" style="font-size:12px">Saisie manuelle : l'app ne se connecte pas à HIBP. Les conseils viennent de mots-clés dans les données exposées ; ils ne remplacent pas la lecture de la fiche de la fuite.</p>
  </div>
 </section>

 <section class="view" data-view="pw" hidden>
  <div class="card" id="pw"><h2>Mot de passe compromis ? <small>— Pwned Passwords</small></h2>
     <p class="mut" style="font-size:13px">Le mot de passe est transformé en empreinte SHA-1 <b>dans ton navigateur</b>. Seuls 5 caractères de cette empreinte partent vers Pwned Passwords (méthode k-anonymat) ; le mot de passe n'est ni envoyé ni enregistré.</p>
     <div class="row"><input type="password" id="pwin" placeholder="mot de passe à tester" autocomplete="off" spellcheck="false" style="flex:1"><button id="pweye" type="button" title="Afficher / masquer la saisie" aria-label="Afficher le mot de passe" aria-pressed="false" style="min-width:42px">👁</button><button id="pwgo">Tester</button></div>
     <p id="pwres" style="margin:10px 0 0"></p>
     <p class="mut" style="font-size:12px">« Trouvé » = ce mot de passe figure dans des fuites connues : ne l'utilise plus nulle part. « Non trouvé » ne prouve pas qu'il est sûr.</p>
  </div>
 </section>

 <section class="view" data-view="name" hidden>
  <div class="card" id="nm"><h2>Recherche par nom <small>— liens à ouvrir toi-même</small></h2>
     <div class="row"><input type="text" id="nmcity" placeholder="ville (facultatif : aide à écarter les homonymes)" style="flex:1;min-width:200px"><input type="text" id="nmjob" placeholder="métier / employeur (facultatif)" style="flex:1;min-width:200px"></div>
     <p class="mut" style="font-size:13px">Utilise le prénom et le nom de « Qui suis-je ? » (rubrique Nouvelle analyse). Chaque lien lance une recherche sur le moteur : ton nom lui est donc transmis. Ce sont des recherches, pas des preuves : vérifie qu'il s'agit bien de toi.</p>
     <div id="nmlinks"></div>
  </div>
 </section>

 <section class="view" data-view="ck" hidden>
  <div class="card ck" id="ck"><h2>À faire à la main <small>— coche au fur et à mesure (enregistré sur ce PC)</small></h2>
    <div class="bar"><i id="ckbar"></i></div><p class="mut" id="cktxt"></p><div id="cklist"></div>
    <p class="mut" style="font-size:12px">Liens écrits de mémoire, non vérifiés un par un : si une page a changé, cherche le nom du service.</p>
  </div>
 </section>

 <section class="view" data-view="journal" hidden>
  <div class="card" id="jr"><h2 style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap"><span>Journal <small>— du plus récent au plus ancien</small></span>
    <span class="row" style="margin:0"><select id="jrtype" aria-label="Filtrer le journal"><option value="">tout</option><option>analyse</option><option>demande</option><option>fuite</option><option>checklist</option><option>rapport</option><option>réglage</option></select><a class="btn" href="/api/journal/export.csv" download>Exporter (CSV)</a></span></h2>
    <div id="jrlist"></div>
    <p class="mut" style="font-size:12px">« reconstitué » : événement déduit des données qui existaient avant le journal (dates d'analyses et de demandes), donc moins précis.</p>
  </div>
 </section>

 <section class="view" data-view="set" hidden>
  <div class="card" id="st"><h2>Dossier de données <small>— où l'application range analyses, fuites et demandes</small></h2>
    <p style="margin:0 0 6px">Dossier utilisé : <b id="stdir"></b> <span id="stsrc" class="mut"></span></p>
    <div class="row"><input type="text" id="stpath" placeholder="nouveau dossier, ex. ~/osint-test (vide = ~/osint)" style="flex:1;min-width:220px">
      <label class="mut" style="font-size:13px;white-space:nowrap;margin:0"><input type="checkbox" id="stcopy"> copier mes données actuelles</label><button id="stgo">Changer</button></div>
    <p id="stmsg" style="margin:6px 0 0"></p>
    <p class="mut" style="font-size:12px">Sans copie, l'application repart à vide dans le nouveau dossier. L'ancien dossier n'est ni modifié ni supprimé. Le changement s'applique au prochain démarrage : ferme la fenêtre puis relance l'application.</p>
  </div>
  <div class="card"><h2>Affichage</h2>
    <p style="margin:0">Disposition et thème se changent dans la barre du haut ; ils sont enregistrés avec l'ordre des tuiles dans <span class="mono" id="stfile"></span>.</p>
  </div>
 </section>
</main>

<aside class="rail" aria-label="Assistant et historique">
  <details class="card" id="asbox" open><summary>Assistant <span class="pill" id="asstate">Ollama</span></summary><div class="in">
    <p class="mut" style="font-size:12.5px;margin-top:0" id="asinfo"></p>
    <div class="row"><input id="asurl" style="flex:1" placeholder="http://127.0.0.1:11434" aria-label="Adresse Ollama"><button onclick="setOllama()" title="Enregistrer l'adresse et tester la connexion">OK</button></div>
    <div class="row"><select id="asmodel" style="flex:1"></select><button onclick="loadModels()" title="Recharger la liste des modèles">↻</button></div>
    <div class="chat" id="aschat"></div>
    <textarea id="asq" rows="2" placeholder="Ex : Quel compte supprimer en premier ?"></textarea>
    <div class="row" style="margin-top:6px"><button class="pri" onclick="ask()">Demander</button><span class="mut" style="font-size:12px">sur l'analyse affichée</span></div>
  </div></details>
  <details class="card" id="hibox" open><summary>Historique <span class="mut" id="hicount" style="font-weight:400;font-size:12.5px"></span></summary><div class="in">
    <div class="hist" id="hist"></div>
  </div></details>
</aside>
</div>

<dialog id="mail" aria-labelledby="mtitle">
  <div class="hd"><b id="mtitle"></b><span style="flex:1"></span><button id="mclose" aria-label="Fermer">✕</button></div>
  <div class="bd">
    <div class="row" id="mtyperow" style="margin:0"><label for="mtype" style="margin:0">Type</label><select id="mtype"><option value="17">Effacement (art. 17)</option><option value="15">Accès (art. 15)</option><option value="15+17">Accès puis effacement (art. 15 et 17)</option></select></div>
    <label for="mto">Destinataire : adresse du DPO ou contact « vie privée » (politique de confidentialité ou mentions légales du site)</label>
    <input type="email" id="mto" placeholder="dpo@site.com">
    <label for="mtext">Texte du mail (modifiable : relis-le avant d'envoyer)</label>
    <textarea id="mtext"></textarea>
    <p class="err" id="merr"></p>
    <p class="mut" style="font-size:12px;margin:0">L'application n'envoie rien elle-même : « Ouvrir ma messagerie » ouvre ton logiciel de mail avec ce texte, et c'est toi qui cliques sur Envoyer. Si rien ne s'ouvre, copie le texte.</p>
  </div>
  <div class="ft"><button id="mcopy">Copier le texte</button><a class="btn" id="mopen" href="#">✉ Ouvrir ma messagerie</a><button id="mlater">Enregistrer « à envoyer »</button><button class="pri" id="msave">Enregistrer comme envoyée</button></div>
</dialog>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const J=(u,o)=>fetch(u,o).then(async r=>{const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.detail||("erreur "+r.status));return d;});
const JSONH={"Content-Type":"application/json"};
let cur=null,timer=null,job=null;
/* ================= coque : rubriques, disposition, thème ================= */
const IC={dash:'<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>',
 scan:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',res:'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
 req:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',leak:'<path d="M12 3s6 7 6 11a6 6 0 0 1-12 0c0-4 6-11 6-11z"/>',
 pw:'<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3"/>',name:'<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
 ck:'<path d="M4 12l5 5L20 6"/>',journal:'<path d="M12 7v5l3 3"/><circle cx="12" cy="12" r="9"/>',set:'<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/>'};
const ic=k=>`<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">${IC[k]}</svg>`;
const VIEWS={dash:"Tableau de bord",scan:"Nouvelle analyse",res:"Résultats",req:"Demandes",leak:"Fuites connues",pw:"Mots de passe",name:"Recherche par nom",ck:"Checklist",journal:"Journal",set:"Réglages"};
const NAV={console:[[null,["dash","scan","res","req","leak","pw","name","ck","journal","set"]]],
 menu:[["Audit",["scan","res"]],["Agir",["req","leak","pw","name"]],["Suivi",["ck","journal","set"]]]};
let UI={layout:"console",theme:"system",tiles:{order:[],hidden:[]}},VIEW=null,BADGE={};
function lsGet(k){try{return localStorage.getItem(k);}catch(e){return null;}}
function lsSet(k,v){try{localStorage.setItem(k,v);}catch(e){}}
function renderNav(){$("side").innerHTML=`<div class="who">127.0.0.1:8300 · local</div>`+NAV[UI.layout].map(([g,items])=>(g?`<div class="grp">${g}</div>`:"")+
  items.map(k=>`<button data-view="${k}" aria-current="${VIEW===k}">${ic(k)}${VIEWS[k]}${BADGE[k]||""}</button>`).join("")).join("");}
function show(v){if(UI.layout==="menu"&&v==="dash")v="res";if(!VIEWS[v])v=UI.layout==="console"?"dash":"res";VIEW=v;lsSet("osint_view",v);
 document.querySelectorAll("section.view").forEach(s=>s.hidden=s.dataset.view!==v);$("crumb").textContent=VIEWS[v];renderNav();
 if(v==="dash")loadDash();if(v==="journal")loadJournal();if(v==="req")loadReqs();if(v==="leak")loadLeaks();}
function applyUI(){document.documentElement.toggleAttribute("data-theme",UI.theme!=="system");if(UI.theme!=="system")document.documentElement.setAttribute("data-theme",UI.theme);
 ["system","dark","light"].forEach(t=>$("th"+t).setAttribute("aria-pressed",UI.theme===t));
 ["console","menu"].forEach(l=>$("ly"+l).setAttribute("aria-pressed",UI.layout===l));}
async function saveUI(part){Object.assign(UI,part);applyUI();try{UI=await J("/api/settings/ui",{method:"PUT",headers:JSONH,body:JSON.stringify(part)});}catch(e){}}
document.addEventListener("click",e=>{const b=e.target.closest("button,a");if(!b)return;
 if(b.dataset.view&&b.closest("#side")){show(b.dataset.view);return;}
 if(b.dataset.go){show(b.dataset.go);return;}
 if(b.dataset.layout){saveUI({layout:b.dataset.layout});show(b.dataset.layout==="console"?"dash":(VIEW==="dash"?"res":VIEW));return;}
 if(b.dataset.themeSet){saveUI({theme:b.dataset.themeSet});return;}
 if(b.dataset.mkreq!==undefined){makeReq(b.dataset.site,b.dataset.url,b.dataset.target||"");return;}
 if(b.dataset.follow){followReq(b.dataset.follow);return;}
 if(b.dataset.relance){relance(b.dataset.relance);return;}});
/* ================= analyse : lancement et suivi ================= */
function addField(box,ph){const d=document.createElement("div");d.className="row";
 d.innerHTML=`<input type="text" placeholder="${ph}"><button onclick="this.parentNode.remove()" aria-label="Retirer">×</button>`;$(box).appendChild(d);d.firstChild.focus();}
const vals=box=>[...$(box).querySelectorAll("input")].map(i=>i.value.trim()).filter(Boolean);
async function start(){
 const body={pseudos:vals("pseudos"),emails:vals("emails"),options:{all_sites:$("allsites").checked,top_sites:+$("top").value,timeout:+$("timeout").value,max_min:+$("maxmin").value,sherlock:$("sherlock").checked,nsfw:$("nsfw").checked,user_scanner:$("userscanner").checked},identity:{first:$("idfirst").value.trim(),last:$("idlast").value.trim()}};
 $("go").disabled=true;$("goerr").textContent="";
 try{const j=await J("/api/jobs",{method:"POST",headers:JSONH,body:JSON.stringify(body)});open_(j.id);show("res");}
 catch(e){$("goerr").textContent=e.message;}finally{$("go").disabled=false;}}
function open_(id){cur=id;$("empty").style.display="none";$("view").style.display="flex";clearInterval(timer);poll();timer=setInterval(poll,2000);}
async function poll(){if(!cur)return;const r=await fetch("/api/jobs/"+cur);if(!r.ok)return;job=await r.json();render();loadHist();
 if(["terminé","annulé","interrompu"].includes(job.state))clearInterval(timer);}
function render(){
 const n=job.targets.length;let part=0;const now=Date.now()/1000,mm=((job.options&&job.options.max_min)||20)*60;
 for(const t of job.targets){if(t.status==="en cours"&&t.started){const exp=t.kind==="email"?180:mm;part+=Math.min(.95,(now-t.started)/exp);}}
 const pct=n?Math.min(100,Math.round(100*(job.done+part)/n)):0,est=part>0?" · estimation selon le temps écoulé":"";
 $("pbar").style.width=pct+"%";$("ptxt").textContent=`${job.done}/${n} cibles traitées (${pct}%${est})`+idleTxt();
 $("state").textContent=job.state;$("state").className="pill s-"+job.state;
 $("tlist").innerHTML=job.targets.map(t=>(covDeg(t.coverage)?degBox(t.coverage,t.value):"")+(covDeg(t.coverage_us)?degBox(t.coverage_us,t.value,"user-scanner"):"")).join("")+job.targets.map(t=>`<div class="row" style="justify-content:space-between"><span>${esc(t.kind)} · <b>${esc(t.value)}</b></span>
  <span><span class="s-${esc(t.status)}">${esc(t.status)}</span> · ${(t.results||[]).length} résultat(s)${t.error?` · <span class="s-erreur">${esc(t.error)}</span>`:""}${t.warn?` · <span class="s-annulé">${esc(t.warn)}</span>`:""}${t.coverage&&!t.warn?` · couverture ${t.coverage.total-t.coverage.blocked}/${t.coverage.total}`:""}${durTxt(t)}</span></div>`).join("");
 const lg=$("log"),atEnd=lg.scrollTop+lg.clientHeight>=lg.scrollHeight-20;
 lg.textContent=job.log.slice(-120).join("\n");if(atEnd)lg.scrollTop=lg.scrollHeight;
 $("cancel").disabled=!["running","queued"].includes(job.state);$("del").disabled=["running","queued"].includes(job.state);
 $("csv").href=`/api/jobs/${cur}/export.csv`;$("json").href=`/api/jobs/${cur}`;
 renderResults();maybeAnalysis();}
const COV_DEGRADED=0.30; // même seuil que COV_DEGRADED côté serveur
const covDeg=c=>!!(c&&c.total)&&c.blocked/c.total>=COV_DEGRADED;
const degBox=(c,who,tool="Holehe")=>{const pc=Math.round(100*c.blocked/c.total);return `<div class="degraded" role="alert"><b>⚠ Test ${esc(tool)} dégradé${who?` (${esc(who)})`:""} : ${pc} % des sites non testables, ne conclus rien.</b><br><span style="font-size:13px">${esc(tool)} n'a pas pu interroger ${c.blocked} site(s) sur ${c.total} (limite de débit ou blocage). « Aucun compte » ne veut rien dire pour ces sites : relance plus tard, change de réseau, ou vérifie-les à la main.</span></div>`;};
function covCard(c,tool){if(!(c&&c.total))return "";const ok=c.total-c.blocked,pc=Math.round(100*ok/c.total);
 return (covDeg(c)?degBox(c,"",tool):"")+`<div class="card" style="margin:6px 0;background:var(--card2)"><b>Couverture ${esc(tool)}</b> : ${ok}/${c.total} sites testés avec succès (${pc} %)
    <div class="bar" style="margin:6px 0"><i style="width:${pc}%;background:${covDeg(c)?"var(--ko)":"var(--ok)"}"></i></div>
    <span class="mut" style="font-size:12.5px">${c.used} compte(s) trouvé(s), ${c.unused} site(s) sans compte, <b>${c.blocked} non testable(s)</b>${c.skipped?`, ${c.skipped} écarté(s) car ils t'enverraient un e-mail`:""}. « Aucun compte » ne prouve rien pour les sites bloqués.</span>
    ${c.blocked?`<details><summary>${c.blocked} site(s) bloqué(s) à vérifier à la main</summary>${c.blocked_sites.map(s=>s.includes(".")?`<a class="badge" href="https://${esc(s)}" target="_blank" rel="noopener noreferrer">${esc(s)}</a>`:`<span class="badge">${esc(s)}</span>`).join(" ")}</details>`:""}</div>`;}
function renderResults(){
 if(!job)return;const f=$("filter").value.toLowerCase();let h="";

 for(const t of job.targets){
  const rows=(t.results||[]).filter(r=>!f||JSON.stringify([t.value,r]).toLowerCase().includes(f));
  h+=`<h3>${esc(t.kind)} : ${esc(t.value)} <small>(${rows.length} / ${(t.results||[]).length})</small></h3>`;
  for(const [c,tool] of [[t.coverage,"Holehe"],[t.coverage_us,"user-scanner"]])h+=covCard(c,tool);
  if(!rows.length){h+=`<p class="mut">${t.status==="terminé"?(covDeg(t.coverage)||covDeg(t.coverage_us)?"Aucun compte trouvé sur les sites testables, mais le test est dégradé : ce résultat ne prouve rien.":t.coverage&&t.coverage.blocked?"Aucun compte trouvé sur les sites testables.":"Rien trouvé."):"—"}</p>`;continue;}
  h+=`<table><tr><th>Site</th><th>Source</th><th>Infos publiques détectées</th><th>Demande</th></tr>`;
  rows.forEach(r=>{
   const kv=Object.entries(r.infos||{}).map(([k,v])=>`<div class="kv"><b>${esc(k)}</b> : ${esc(v)}</div>`).join("")||`<span class="mut">compte détecté, pas de détail public</span>`;
   const safe=/^https?:\/\//.test(r.url);
   h+=`<tr><td>${safe?`<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.site)}</a>`:esc(r.site)}<br><small>${esc((r.tags||[]).join(", "))}</small></td>
    <td>${esc(r.source)}</td><td>${kv}</td><td>${reqCell(r.site,r.url,t.kind==="email"?`à l'adresse email ${t.value}`:`au pseudo « ${t.value} »`)}</td></tr>`;});
  h+="</table>";}
 $("results").innerHTML=h||"";}
async function cancelJob(){if(cur)await fetch(`/api/jobs/${cur}/cancel`,{method:"POST"});}
let HIST=[];
async function loadHist(){try{HIST=await J("/api/jobs");}catch(e){HIST=[];}
 $("hicount").textContent=HIST.length?`${HIST.length} analyse(s)`:"";
 $("hist").innerHTML=HIST.map(j=>`<div onclick="open_('${esc(j.id)}');show('res')" style="${j.id===cur?"color:var(--acc);font-weight:600":""}">${new Date(j.created*1000).toLocaleString("fr-FR",{dateStyle:"short",timeStyle:"short"})} · <span class="s-${esc(j.state)}">${esc(j.state)}</span> · ${j.found} résultat(s)<br><small>${esc(j.targets.join(", "))}</small></div>`).join("")||`<span class="mut">Aucune analyse.</span>`;}
const fmtS=s=>{s=Math.max(0,Math.round(s));return Math.floor(s/60)+":"+String(s%60).padStart(2,"0");};
const nowS=()=>Date.now()/1000;
function durTxt(t){if(!t.started)return"";if(t.finished)return` · durée ${fmtS(t.finished-t.started)}`;return t.status==="en cours"?` · ${fmtS(nowS()-t.started)} écoulées`:"";}
function idleTxt(){if(!job||job.state!=="running"||!job.last_activity)return"";const s=nowS()-job.last_activity;
 return` · dernière activité il y a ${fmtS(s)}`+(s>120?" (silence normal : Maigret n'affiche que les comptes trouvés ; l'outil est arrêté tout seul à la durée max)":"");}
async function delJob(){if(!cur||!confirm("Supprimer définitivement cette analyse et ses fichiers ?"))return;
 try{await J(`/api/jobs/${cur}`,{method:"DELETE"});}catch(e){alert(e.message);return;}
 clearInterval(timer);cur=null;job=null;anFor=null;AN=null;$("view").style.display="none";$("an").style.display="none";$("empty").style.display="block";loadHist();}
let anFor=null,anTimer=null,asking=false,AN=null;const chat=[];
function maybeAnalysis(){if(!job||!["terminé","annulé","interrompu"].includes(job.state))return;if(anFor===cur)return;anFor=cur;chat.length=0;$("aschat").innerHTML="";loadAnalysis();loadCompare();}
const idq=()=>"first="+encodeURIComponent($("idfirst").value.trim())+"&last="+encodeURIComponent($("idlast").value.trim());
async function loadAnalysis(){if(!cur)return;const r=await fetch(`/api/jobs/${cur}/analysis?`+idq());if(!r.ok)return;AN=await r.json();renderAnalysis();}
function idChanged(){lsSet("osint_id",JSON.stringify([$("idfirst").value,$("idlast").value]));
 clearTimeout(anTimer);anTimer=setTimeout(()=>{if(anFor===cur&&cur)loadAnalysis()},600);}
function bars(o){const e=Object.entries(o||{}).sort((x,y)=>y[1]-x[1]);const m=Math.max(1,...e.map(x=>x[1]));
 return e.map(([k,v])=>`<div class="hb"><span>${esc(k)}</span><div class="hbar"><i style="width:${Math.round(100*v/m)}%"></i></div><b>${v}</b></div>`).join("")||`<span class="mut">—</span>`;}
function card(it,i){const safe=/^https?:\/\//.test(it.url);const hot=it.level==="prioritaire";
 return `<div class="ai ${esc(it.css)}"><div class="row" style="justify-content:space-between"><b>${safe?`<a href="${esc(it.url)}" target="_blank" rel="noopener noreferrer">${esc(it.site)}</a>`:esc(it.site)}</b><span class="pill">${esc(it.level)}</span></div>
 <div><span class="badge">${esc(it.category)}</span><span class="badge${it.sensitivity==="élevée"?" hot":""}">sensibilité ${esc(it.sensitivity)}</span><span class="badge${hot?" hot":""}">correspondance : ${esc(it.match_label)}</span><span class="badge">${esc(it.kind)} ${esc(it.target)}</span><span class="badge">${esc(it.source)}</span></div>
 <p>${esc(it.explain)}</p><p><b>À faire :</b> ${esc(it.action)}</p>
 <div>${it.fields.map(f=>`<span class="badge${it.risky.includes(f)?" hot":""}">${esc(f)}</span>`).join("")}</div>
 <div class="row">${reqCell(it.site,it.url,it.kind==="email"?`à l'adresse email ${it.target}`:`au pseudo « ${it.target} »`)}<button onclick="askAbout(${i})">Demander à l'assistant</button></div></div>`;}
function renderAnalysis(){if(!AN)return;const s=AN.summary;$("an").style.display="flex";
 $("kpis").innerHTML=[["Comptes détectés",s.total],["À traiter en priorité",s.by_level["prioritaire"]||0],["À vérifier",s.by_level["à vérifier"]||0],["Catégories sensibles",s.sensitive]]
  .map(([l,v])=>`<div class="kpi"><b>${v}</b><span>${l}</span></div>`).join("");
 $("ch_cat").innerHTML=bars(s.by_category);$("ch_match").innerHTML=bars(s.by_match);$("ch_fields").innerHTML=bars(s.exposed_fields);
 $("plan").innerHTML=s.plan.map(x=>`<li>${esc(x)}</li>`).join("");
 const main=[],low=[];AN.items.forEach((it,i)=>(it.level==="faible"?low:main).push(card(it,i)));
 $("anitems").innerHTML=(main.join("")||`<p class="mut">Aucun compte prioritaire ou à vérifier.</p>`)+(low.length?`<details><summary>${low.length} compte(s) à faible priorité</summary>${low.join("")}</details>`:"");}
/* ================= assistant ================= */
async function loadModels(){let d;try{d=await (await fetch("/api/assistant/models")).json();}catch(e){d={ok:false,error:String(e)}}
 showModels(d);}
async function setOllama(){let d;try{d=await J("/api/settings/ollama",{method:"POST",headers:JSONH,body:JSON.stringify({url:$("asurl").value})});}catch(e){d={ok:false,url:$("asurl").value,error:e.message}}
 showModels(d);if(d.note)$("asinfo").textContent+=" "+d.note;}
function showModels(d){if(d.url)$("asurl").value=d.url;
 const sel=$("asmodel"),prev=sel.value;
 if(d.ok&&d.models.length){sel.innerHTML=d.models.map(m=>`<option>${esc(m)}</option>`).join("");if(d.models.includes(prev))sel.value=prev;
  $("asstate").textContent="Ollama";$("asstate").className="pill p-ok";
  $("asinfo").textContent=`Sur ton serveur Ollama (${d.url}) : rien ne part dans le cloud. Il explique les résultats et peut se tromper.`;}
 else{sel.innerHTML="";$("asstate").textContent="indisponible";$("asstate").className="pill p-ko";$("asinfo").textContent=`Ollama injoignable (${d.url}). ${d.error||""} Indique l'adresse de ton serveur Ollama ci-dessous (ex. http://192.168.1.169:11434) puis OK.`;}
 OLLAMA_OK=!!(d.ok&&d.models.length);}
let OLLAMA_OK=false;
function addMsg(c,t){const d=document.createElement("div");d.className=c;d.textContent=t;$("aschat").appendChild(d);d.scrollIntoView({block:"nearest"});return d;}
function askAbout(i){const it=AN.items[i];$("asbox").open=true;ask(`Explique-moi le résultat « ${it.site} » (${it.url}) : que signifie-t-il pour moi et que dois-je faire ?`);}
async function ask(q){q=q||$("asq").value.trim();if(!q||asking)return;
 if(!cur){addMsg("a","Ouvre d'abord une analyse (historique) : l'assistant répond sur l'analyse affichée.");return;}
 const model=$("asmodel").value;if(!model){addMsg("a","Aucun modèle disponible : Ollama est injoignable.");return;}
 asking=true;$("asq").value="";addMsg("u",q);const w=addMsg("a","… réflexion en cours (peut durer une minute)");
 try{const j=await J(`/api/jobs/${cur}/assistant`,{method:"POST",headers:JSONH,body:JSON.stringify({question:q,model,history:chat.slice(-6),first:$("idfirst").value.trim(),last:$("idlast").value.trim()})});
  w.textContent=j.answer;chat.push({role:"user",content:q},{role:"assistant",content:j.answer});}
 catch(e){w.textContent="Erreur : "+e.message;}finally{asking=false;}}
/* ================= checklist ================= */
const CK=[
 {g:"Chercher à la main",i:[
  ["wmn","Tester tes pseudos sur WhatsMyName (version navigateur) pour recouper Maigret et Sherlock.","https://whatsmyname.app"],
  ["gname","Chercher « Prénom Nom » entre guillemets, avec ta ville ou ton employeur, en navigation privée."],
  ["gres","Dans ton compte Google, demander le retrait de ton téléphone, adresse ou email via « Résultats vous concernant »."],
  ["hibpweb","Tester chacun de tes emails sur haveibeenpwned.com et activer l'alerte gratuite de nouvelle fuite.","https://haveibeenpwned.com"],
  ["blk","Vérifier à la main les sites que Holehe n'a pas pu tester (liste dans « Couverture Holehe »), surtout ceux que tu utilises ou as utilisés."],
  ["hibpkey","Prendre la clé API HIBP, puis la brancher dans l'appli (variable HIBP_API_KEY)."],
  ["annu","Chercher ton nom dans les annuaires et registres d'entreprises (Pappers, Societe.com) si tu es dirigeant.","https://www.pappers.fr"],
  ["ads","Regarder tes préférences publicitaires : Google My Ad Center, Meta, Amazon, Apple.","https://myadcenter.google.com"]]},
 {g:"Sécuriser",i:[
  ["mgr","Utiliser un gestionnaire de mots de passe."],
  ["uniq","Un mot de passe unique par site, en commençant par la messagerie, la banque et les réseaux sociaux."],
  ["mfa","Activer la double authentification (clé d'accès / passkey si possible), surtout sur ta messagerie."],
  ["reco","Vérifier l'email et le téléphone de récupération de tes comptes principaux."],
  ["old","Supprimer les comptes inutilisés trouvés par l'analyse (rubrique Résultats)."],
  ["alias","Utiliser un alias d'email différent par nouveau site (SimpleLogin, addy.io…) pour repérer qui fuit ton adresse.","https://simplelogin.io"]]},
 {g:"Demander et surveiller",i:[
  ["rgpd","Envoyer les demandes RGPD (accès / effacement) pour les comptes prioritaires, via « Faire une demande »."],
  ["rgpd1m","Noter la date d'envoi : le site a un mois pour répondre. Sans réponse, saisir la CNIL.","https://www.cnil.fr"],
  ["bank","Surveiller les relevés bancaires et les alertes de connexion."],
  ["phish","Rester méfiant sur les mails ou SMS qui citent tes données (hameçonnage)."],
  ["cyber","En cas de problème : cybermalveillance.gouv.fr (assistance), signal-spam.fr (spam).","https://www.cybermalveillance.gouv.fr"]]}];
let ckDone={};
const CKTXT=Object.fromEntries(CK.flatMap(g=>g.i.map(([id,t])=>[id,t])));
async function loadChecks(){try{ckDone=(await J("/api/checklist")).done||{};}catch(e){}renderChecks();}
function ckCount(){let n=0,t=0;CK.forEach(g=>g.i.forEach(([id])=>{t++;if(ckDone[id])n++;}));return [n,t];}
function renderChecks(){const [n,t]=ckCount();
 $("cklist").innerHTML=CK.map(g=>`<h3>${esc(g.g)}</h3>`+g.i.map(([id,txt,url])=>{const d=!!ckDone[id];
  return `<label class="${d?"dn":""}"><input type="checkbox" ${d?"checked":""} onchange="toggleCheck('${id}',this.checked)"><span>${esc(txt)}${url?` <a href="${esc(url)}" target="_blank" rel="noopener noreferrer">↗ ouvrir</a>`:""}</span></label>`;}).join("")).join("");
 $("ckbar").style.width=(t?Math.round(100*n/t):0)+"%";$("cktxt").textContent=`${n}/${t} faits`;}
async function toggleCheck(id,v){ckDone[id]=v;renderChecks();
 try{await fetch("/api/checklist",{method:"PUT",headers:JSONH,body:JSON.stringify({id,done:v,label:(CKTXT[id]||"").slice(0,120)})});}catch(e){}}
/* ================= mots de passe ================= */
async function sha1hex(t){if(!(window.crypto&&crypto.subtle))throw new Error("Contexte non sécurisé : ouvre l'app via http://127.0.0.1:8300");
 const b=await crypto.subtle.digest("SHA-1",new TextEncoder().encode(t));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("").toUpperCase();}
async function pwCheck(){
 const v=$("pwin").value,out=$("pwres");if(!v){out.textContent="Saisis un mot de passe.";return;}
 out.className="mut";out.textContent="Vérification…";
 try{const h=await sha1hex(v),pre=h.slice(0,5),suf=h.slice(5);
  const r=await fetch("/api/pwned/range/"+pre);if(!r.ok){let d="";try{d=(await r.json()).detail}catch(e){}throw new Error(d||("HTTP "+r.status));}
  const txt=await r.text();let n=0;
  for(const l of txt.split(/\r?\n/)){const [s2,c]=l.trim().split(":");if(s2===suf){n=parseInt(c,10)||0;break;}}
  if(n>0){out.className="s-erreur";out.textContent="⚠ Trouvé dans des fuites : "+n.toLocaleString("fr-FR")+" fois. Change-le partout où tu l'utilises.";}
  else{out.className="s-terminé";out.textContent="Non trouvé dans les fuites connues.";}
 }catch(e){out.className="s-erreur";out.textContent="Erreur : "+e.message;}
 finally{$("pwin").value="";pwShow(false);}}
function pwShow(on){$("pwin").type=on?"text":"password";$("pweye").textContent=on?"🙈":"👁";$("pweye").setAttribute("aria-pressed",on?"true":"false");$("pweye").setAttribute("aria-label",on?"Masquer le mot de passe":"Afficher le mot de passe");}
$("pweye").onclick=()=>{pwShow($("pwin").type==="password");$("pwin").focus();};
$("pwgo").onclick=pwCheck;$("pwin").addEventListener("keydown",e=>{if(e.key==="Enter")pwCheck();});
/* ================= fuites : liste, ajout, import ================= */
let LK=[];
async function loadLeaks(){try{LK=(await J("/api/leaks")).leaks||[];}catch(e){LK=[];}
 $("lklist").innerHTML=LK.length?LK.map(x=>`<div style="border-top:1px solid var(--line);padding:10px 0"><div class="row" style="justify-content:space-between"><span><b>${esc(x.service)}</b>${x.date?` · ${esc(x.date)}`:""}${x.address?` · <span class="mut">${esc(x.address)}</span>`:""}</span><button onclick="delLeak('${esc(x.id)}')" title="Supprimer cette ligne" aria-label="Supprimer">×</button></div>${x.data?`<div class="mut" style="font-size:13px">Données : ${esc(x.data)}</div>`:""}<ul style="margin:6px 0 0 18px;font-size:13px">${x.advice.map(a=>`<li>${esc(a)}</li>`).join("")}</ul></div>`).join(""):`<p class="mut" style="font-size:13px">Aucune fuite notée.</p>`;
 updBadges();}
async function addLeak(){$("lkerr").textContent="";const b={address:$("lkaddr").value,service:$("lksvc").value,date:$("lkdate").value,data:$("lkdata").value};
 if(!b.service.trim()){$("lkerr").textContent="Indique le service ou le site.";return;}
 try{await J("/api/leaks",{method:"POST",headers:JSONH,body:JSON.stringify(b)});}catch(e){$("lkerr").textContent=e.message;return;}
 ["lksvc","lkdate","lkdata"].forEach(i=>$(i).value="");await loadLeaks();if(cur)loadAnalysis();}
async function delLeak(id){if(!confirm("Supprimer cette fuite de la liste ?"))return;await fetch("/api/leaks/"+id,{method:"DELETE"});await loadLeaks();if(cur)loadAnalysis();}
$("lkadd").onclick=addLeak;$("lkdata").addEventListener("keydown",e=>{if(e.key==="Enter")addLeak();});
const lkKey=x=>[x.service,x.date,x.address].map(v=>String(v||"").trim().toLowerCase()).join("|");
let LKIMP=null;
$("lkimpbtn").onclick=()=>$("lkfile").click();
$("lkfile").onchange=e=>{const f=e.target.files[0];e.target.value="";if(!f)return;const r=new FileReader();
 r.onload=()=>{const box=$("lkimp");box.hidden=false;let d;try{d=JSON.parse(r.result);if(d&&!Array.isArray(d)&&Array.isArray(d.leaks))d=d.leaks;if(!Array.isArray(d))throw 0;}
  catch(_){box.innerHTML=`<p class="err" style="margin:0">« ${esc(f.name)} » n'est pas un export de fuites (liste JSON attendue). Rien n'a été importé.</p>`;LKIMP=null;return;}
  const have=new Set(LK.map(lkKey)),valid=d.filter(x=>x&&typeof x==="object"&&String(x.service||"").trim()),nw=valid.filter(x=>!have.has(lkKey(x)));
  LKIMP=valid;box.innerHTML=`<b>Aperçu de « ${esc(f.name)} »</b><p style="margin:6px 0">${d.length} ligne(s) · ${valid.length-nw.length} déjà présente(s) · <b>${nw.length} nouvelle(s)</b>${d.length-valid.length?` · ${d.length-valid.length} invalide(s)`:""}</p>
   ${nw.length?`<ul style="margin:0 0 8px 18px;font-size:13px">${nw.slice(0,8).map(x=>`<li>${esc(x.service)}${x.date?" · "+esc(x.date):""}</li>`).join("")}${nw.length>8?`<li>…</li>`:""}</ul>`:""}
   <div class="row" style="margin:0"><button class="pri" id="lkimpgo" ${nw.length?"":"disabled"}>Importer ${nw.length} fuite(s)</button><button id="lkimpno">Annuler</button></div>
   <p class="mut" style="font-size:12px;margin:6px 0 0">Fusion sans doublon (même service, date et adresse) : rien n'est supprimé ni remplacé.</p>`;
  $("lkimpno").onclick=()=>{box.hidden=true;LKIMP=null;};
  $("lkimpgo").onclick=async()=>{try{const res=await J("/api/leaks/import",{method:"POST",headers:JSONH,body:JSON.stringify(LKIMP)});
    box.innerHTML=`<p style="margin:0" class="s-terminé">${res.added} fuite(s) importée(s), ${res.skipped} ignorée(s).</p>`;LKIMP=null;await loadLeaks();if(cur)loadAnalysis();}
   catch(err){box.innerHTML=`<p class="err" style="margin:0">${esc(err.message)}</p>`;}};};
 r.readAsText(f);};
/* ================= demandes : faire / suivre, mail type ================= */
let RQ=[];
const frd=iso=>{if(!iso)return"";const [y,m,d]=iso.split("-");return `${d}/${m}/${y}`;};
const today=()=>new Date().toISOString().slice(0,10);
const rqWaiting=r=>r.status==="envoyée"||r.status==="relancée";
const normU=u=>String(u||"").toLowerCase().replace(/^https?:\/\/(www\.)?/,"").replace(/[?#].*$/,"").replace(/\/+$/,"");
function findReq(site,url){const u=normU(url),s=String(site||"").trim().toLowerCase();
 return RQ.find(r=>(u&&normU(r.url)===u))||RQ.find(r=>s&&String(r.site||"").trim().toLowerCase()===s);}
function reqPill(r){if(!r)return"";if(r.status==="effacé")return`<span class="pill p-ok">effacé</span>`;if(r.status==="refusée")return`<span class="pill p-ko">refusée</span>`;
 if(rqWaiting(r))return r.overdue?`<span class="pill p-ko">en retard de ${-r.days_left} j</span>`:`<span class="pill p-warn">${esc(r.status)} · ${r.days_left} j</span>`;
 return `<span class="pill">${esc(r.status)}</span>`;}
function reqCell(site,url,ident){const r=findReq(site,url);
 if(r)return `${reqPill(r)} <button data-follow="${esc(r.id)}">Suivre la demande</button>`;
 return `<button class="pri" data-mkreq data-site="${esc(site)}" data-url="${esc(/^https?:\/\//.test(url||"")?url:"")}" data-target="${esc(ident||"")}">✉ Faire une demande</button>`;}
async function loadReqs(){try{RQ=(await J("/api/requests")).requests||[];}catch(e){RQ=[];}renderReqs();updBadges();if(job)renderResults();if(AN)renderAnalysis();if(VIEW==="dash")loadDash();}
function dueBadge(r){if(!r.due||!rqWaiting(r))return"";
 if(r.overdue)return `<span class="badge hot">en retard de ${-r.days_left} j (échéance ${frd(r.due)})</span>`;
 return `<span class="badge">échéance dans ${r.days_left} j (${frd(r.due)})</span>`;}
const ART={"15":"accès (art. 15)","17":"effacement (art. 17)","15+17":"accès + effacement"};
function renderReqs(){const sel=r=>["à envoyer","envoyée","relancée","réponse reçue","effacé","refusée"].map(o=>`<option${o===r.status?" selected":""}>${o}</option>`).join("");
 $("rqlist").innerHTML=RQ.length?RQ.map(r=>{const safe=/^https?:\/\//.test(r.url||"");
  return `<div id="rq-${esc(r.id)}" style="border-top:1px solid var(--line);padding:10px 0"><div class="row" style="justify-content:space-between"><span><b>${safe?`<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.site)}</a>`:esc(r.site)}</b> <span class="badge">${esc(r.kind)}</span>${r.art?`<span class="badge">${esc(ART[r.art]||r.art)}</span>`:""} ${dueBadge(r)}</span>
   <span class="row" style="margin:0"><select aria-label="Statut" onchange="updReq('${esc(r.id)}','status',this.value)">${sel(r)}</select><input type="date" value="${esc(r.sent||"")}" title="Date d'envoi" onchange="updReq('${esc(r.id)}','sent',this.value)"><button onclick="delReq('${esc(r.id)}')" title="Supprimer cette demande" aria-label="Supprimer">×</button></span></div>
   <div class="row"><input type="email" value="${esc(r.to||"")}" placeholder="destinataire (DPO)" style="flex:1;min-width:160px" onchange="updReq('${esc(r.id)}','to',this.value)"><input type="text" value="${esc(r.ref||"")}" placeholder="n° de dossier" style="flex:1;min-width:110px" onchange="updReq('${esc(r.id)}','ref',this.value)"><input type="text" value="${esc(r.note||"")}" placeholder="note" style="flex:2;min-width:160px" onchange="updReq('${esc(r.id)}','note',this.value)"></div>
   <div class="row">${r.status==="à envoyer"?`<button class="pri" onclick="resend('${esc(r.id)}')">✉ Préparer le mail</button>`:`<button data-relance="${esc(r.id)}">✉ Relancer</button>`}${safe?`<button onclick="checkReq('${esc(r.id)}')">Vérifier la page</button>`:""}${r.last_check?`<span class="mut" style="font-size:12.5px">vérifié le ${esc(r.last_check.at)} : ${esc(r.last_check.text)}</span>`:""}</div></div>`;}).join("")
  :`<p class="mut" style="font-size:13px">Aucune demande pour l'instant. Dans Résultats, « Faire une demande » sur un compte prépare le mail et l'ajoute ici.</p>`;}
async function reqCall(method,url,body){try{const d=await J(url,{method,headers:JSONH,body:body?JSON.stringify(body):undefined});$("rqerr").textContent="";return d;}
 catch(e){$("rqerr").textContent=e.message;return null;}}
async function addReq(){const b={site:$("rqsite").value,url:$("rqurl").value,kind:$("rqkind").value,status:$("rqstatus").value,sent:$("rqsent").value,ref:$("rqref").value,note:$("rqnote").value};
 if(!b.site.trim()){$("rqerr").textContent="Indique le site ou l'organisme.";return;}
 if(await reqCall("POST","/api/requests",b)){["rqsite","rqurl","rqsent","rqref","rqnote"].forEach(i=>$(i).value="");$("rqstatus").value="à envoyer";await loadReqs();}}
async function updReq(id,k,v){await reqCall("PUT","/api/requests/"+id,{[k]:v});await loadReqs();}
async function delReq(id){if(!confirm("Supprimer cette demande du suivi ?"))return;await reqCall("DELETE","/api/requests/"+id);await loadReqs();}
async function checkReq(id){const r=await reqCall("POST",`/api/requests/${id}/check`);if(r)await loadReqs();}
$("rqadd").onclick=addReq;
function followReq(id){show("req");setTimeout(()=>{const el=$("rq-"+id);if(el){el.scrollIntoView({behavior:"smooth",block:"center"});el.classList.remove("flash");void el.offsetWidth;el.classList.add("flash");}},80);}
const myName=()=>(($("idfirst").value+" "+$("idlast").value).trim())||"[Prénom Nom]";
function demandText(type,site,url,ident){
 const who=ident?`associé ${ident}`:"";const page=url?`\nPage concernée : ${url}\n`:"";
 const acc=`- la confirmation que vous traitez des données me concernant ;
- une copie de l'ensemble de ces données ;
- les finalités du traitement, les catégories de données, les destinataires (y compris hors UE) ;
- la durée de conservation prévue ;
- l'origine des données qui n'auraient pas été collectées auprès de moi.`;
 const head=type==="15"?"Demande d'accès à mes données personnelles (article 15 du RGPD)":type==="17"?"Demande d'effacement de mes données personnelles (article 17 du RGPD)":"Demande d'accès puis d'effacement de mes données personnelles (articles 15 et 17 du RGPD)";
 let body=`Madame, Monsieur,

Je suis titulaire d'un compte (ou d'une inscription) sur ${site}${who?", "+who:""}.
${page}`;
 if(type==="15"||type==="15+17")body+=`
Conformément à l'article 15 du RGPD, je vous demande de me communiquer :
${acc}
`;
 if(type==="17"||type==="15+17")body+=`
Conformément à l'article 17 du RGPD, je vous demande ${type==="15+17"?"ensuite ":""}l'effacement de mon compte et de toutes les données associées, ainsi que la notification de cet effacement aux tiers destinataires (article 19).
`;
 body+=`
Vous disposez d'un mois pour répondre (article 12.3 du RGPD). Si une vérification d'identité est nécessaire, merci de m'indiquer le moyen sécurisé de vous la transmettre. À défaut de réponse, je saisirai la CNIL.

Cordialement,
${myName()}`;
 return `Objet : ${head}\n\n${body}`;}
function relanceText(r){
 const what=r.kind==="source"?(r.art==="15"?"d'accès (article 15 du RGPD) à mes données personnelles":"d'effacement (article 17 du RGPD) de mes données personnelles"):"de déréférencement de mes données personnelles";
 const delai=r.due?(r.overdue?`est dépassé depuis le ${frd(r.due)}`:`arrive à échéance le ${frd(r.due)}`):"est d'un mois à compter de la réception";
 return `Objet : Relance : ma demande ${what.split(" (")[0].replace(" à mes données personnelles","").replace(" de mes données personnelles","")}${r.sent?" du "+frd(r.sent):""}${r.ref?" (réf. "+r.ref+")":""}

Madame, Monsieur,

${r.sent?"Le "+frd(r.sent)+", je":"Je"} vous ai adressé une demande ${what}${r.url?", concernant la page suivante : "+r.url:""}.${r.ref?" Référence de mon dossier : "+r.ref+".":""}

À ce jour, je n'ai reçu aucune réponse. Le délai d'un mois prévu à l'article 12.3 du RGPD ${delai} (il ne peut être prolongé de deux mois que pour une demande complexe, et à condition de m'en informer).

Je vous demande de me confirmer par écrit la suite donnée à ma demande sous huit jours. À défaut, je saisirai la CNIL.

Cordialement,
${myName()}`;}
/* fenêtre de mail : mode "new" (nouvelle demande), "resend" (demande « à envoyer »), "relance" */
let MAIL=null;
function mailHref(){const raw=$("mtext").value.replace(/\r/g,"");const lines=raw.split("\n");let subj="",body=raw;
 if(/^objet\s*:/i.test(lines[0])){subj=lines[0].replace(/^objet\s*:\s*/i,"");body=lines.slice(1).join("\n").replace(/^\n+/,"");}
 const to=$("mto").value.trim().replace(/[^\w.@+-]/g,"");
 return `mailto:${to}?subject=${encodeURIComponent(subj)}&body=${encodeURIComponent(body)}`;}
function updMailHref(){$("mopen").href=mailHref();}
function openMail(m){MAIL=m;$("merr").textContent="";$("mtitle").textContent=m.title;$("mto").value=m.to||"";
 $("mtyperow").hidden=m.mode==="relance";$("mtype").value=m.type||"17";
 $("mlater").hidden=m.mode!=="new";$("msave").textContent=m.mode==="relance"?"Noter la relance":"Enregistrer comme envoyée";
 $("mtext").value=m.text();updMailHref();$("mail").showModal();$("mto").focus();}
$("mtype").onchange=()=>{if(MAIL){MAIL.type=$("mtype").value;$("mtext").value=MAIL.text();updMailHref();}};
$("mto").oninput=updMailHref;$("mtext").oninput=updMailHref;
$("mclose").onclick=()=>$("mail").close();
$("mcopy").onclick=()=>{const t=$("mtext").value;(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(()=>{$("mcopy").textContent="Copié ✓";setTimeout(()=>$("mcopy").textContent="Copier le texte",1500);},()=>{$("mtext").select();});};
$("mopen").addEventListener("click",e=>{const to=$("mto").value.trim();if(to&&!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)){e.preventDefault();$("merr").textContent="Adresse du destinataire invalide.";}});
function makeReq(site,url,ident){openMail({mode:"new",title:"Faire une demande · "+site,site,url,ident,type:"17",to:"",text(){return demandText(this.type,site,url,ident);}});}
function resend(id){const r=RQ.find(x=>x.id===id);if(!r)return;openMail({mode:"resend",title:"Envoyer la demande · "+r.site,id,type:r.art||"17",to:r.to||"",text(){return demandText(this.type,r.site,r.url,"");}});}
function relance(id){const r=RQ.find(x=>x.id===id);if(!r)return;openMail({mode:"relance",title:"Relancer · "+r.site,id,to:r.to||"",text(){return relanceText(r);}});}
async function saveMail(sent){const m=MAIL;if(!m)return;const to=$("mto").value.trim();
 try{if(m.mode==="new")await J("/api/requests",{method:"POST",headers:JSONH,body:JSON.stringify({site:m.site,url:m.url||"",kind:"source",art:m.type,to,status:sent?"envoyée":"à envoyer",sent:sent?today():""})});
  else if(m.mode==="resend")await J("/api/requests/"+m.id,{method:"PUT",headers:JSONH,body:JSON.stringify({art:m.type,to,status:"envoyée",sent:today()})});
  else await J("/api/requests/"+m.id,{method:"PUT",headers:JSONH,body:JSON.stringify({to,status:"relancée",note:((RQ.find(x=>x.id===m.id)||{}).note||"")+(((RQ.find(x=>x.id===m.id)||{}).note)?" · ":"")+"relancée le "+frd(today())})});
 }catch(e){$("merr").textContent=e.message;return;}
 $("mail").close();await loadReqs();}
$("msave").onclick=()=>saveMail(true);$("mlater").onclick=()=>saveMail(false);
/* ================= comparaison, recherche par nom ================= */
async function loadCompare(){const id=cur;$("cmp").innerHTML="";if(!id)return;let d;try{d=await J(`/api/jobs/${id}/compare`);}catch(e){return;}
 if(id!==cur)return;
 if(!d.previous){$("cmp").innerHTML=`<h3>Comparaison</h3><p class="mut" style="font-size:13px">Pas d'analyse précédente terminée avec les mêmes cibles. Relance-en une plus tard : l'app montrera ce qui est apparu ou disparu.</p>`;return;}
 const list=a=>a.length?`<ul style="margin:4px 0 0 18px;font-size:13px">${a.map(x=>`<li>${esc(x.site)} <span class="mut">(${esc(x.target)})</span> ${/^https?:\/\//.test(x.url)?`<a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">lien</a>`:""}</li>`).join("")}</ul>`:"";
 $("cmp").innerHTML=`<h3>Comparaison avec l'analyse du ${new Date(d.previous.created*1000).toLocaleString("fr-FR")}</h3>
  <div><span class="badge${d.new.length?" hot":""}">${d.new.length} nouveau(x)</span><span class="badge">${d.gone.length} disparu(s)</span><span class="badge">${d.same} inchangé(s)</span></div>
  ${d.new.length?`<details open><summary>Nouveaux comptes</summary>${list(d.new)}</details>`:""}
  ${d.gone.length?`<details><summary>Comptes non retrouvés cette fois</summary>${list(d.gone)}</details>`:""}
  ${d.caveats.length?`<p class="mut" style="font-size:12.5px">⚠ « Disparu » veut seulement dire « non détecté cette fois ». ${esc(d.caveats.join(" · "))}.</p>`:`<p class="mut" style="font-size:12.5px">« Disparu » peut aussi venir d'un site qui a bloqué le scan : vérifie à la main avant de conclure à une suppression.</p>`}`;}
function renderNm(){const f=$("idfirst").value.trim(),l=$("idlast").value.trim(),city=$("nmcity").value.trim(),jb=$("nmjob").value.trim();
 lsSet("nm_extra",JSON.stringify([city,jb]));
 if(!f&&!l){$("nmlinks").innerHTML=`<p class="mut">Renseigne ton prénom et ton nom dans « Qui suis-je ? » (rubrique Nouvelle analyse) pour générer les liens.</p>`;return;}
 const nm=`"${(f+" "+l).trim()}"`,g=q=>"https://www.google.com/search?q="+encodeURIComponent(q);
 const ex=[city,jb].filter(Boolean).map(x=>`"${x}"`).join(" ");
 const site=d=>g(`${nm} site:${d}`+(city?` "${city}"`:""));
 const L=(u,t)=>`<a class="badge" style="text-decoration:none;display:inline-block;margin:3px 4px 3px 0" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t)}</a>`;
 const grp=(t,items,note)=>`<h3>${esc(t)}</h3>${note?`<p class="mut" style="font-size:12.5px;margin:0 0 4px">${esc(note)}</p>`:""}<div>${items.join("")}</div>`;
 $("nmlinks").innerHTML=
  grp("Moteurs de recherche",[L(g(nm),"Google : nom"),ex?L(g(nm+" "+ex),"Google : nom + ville / métier"):"",L("https://www.bing.com/search?q="+encodeURIComponent(nm),"Bing : nom"),L("https://duckduckgo.com/?q="+encodeURIComponent(nm),"DuckDuckGo : nom"),L("https://www.google.com/search?tbm=isch&q="+encodeURIComponent(nm),"Google Images : nom")].filter(Boolean))+
  grp("Annuaires et registres (France)",["pagesjaunes.fr","118712.fr","societe.com","pappers.fr","infogreffe.fr","copainsdavant.linternaute.com"].map(d=>L(site(d),d)),"Recherche Google limitée à chaque site.")+
  grp("Réseaux et plateformes",["linkedin.com","facebook.com","instagram.com","x.com","youtube.com"].map(d=>L(site(d),d)))+
  grp("Sites de recherche de personnes (surtout USA / UK)",["spokeo.com","radaris.com","peekyou.com","whitepages.com","beenverified.com","mylife.com"].map(d=>L(site(d),d)),"Rarement utiles pour une personne en France : vérifie quand même.")+
  `<h3>Aide</h3><p style="font-size:13px"><a href="https://www.cnil.fr/fr/comprendre-mes-droits/le-droit-leffacement-supprimer-vos-donnees-en-ligne" target="_blank" rel="noopener noreferrer">CNIL : le droit à l'effacement</a> <span class="mut">(adresse tirée de ton guide, non vérifiée par moi)</span>. Pour chaque page à supprimer, ajoute-la dans « Demandes ».</p>`;}
/* ================= journal, réglages ================= */
async function loadJournal(){let d={events:[]};try{d=await J("/api/journal?limit=300"+($("jrtype").value?"&type="+encodeURIComponent($("jrtype").value):""));}catch(e){}
 $("jrlist").innerHTML=(d.events||[]).length?d.events.map(evHtml).join(""):'<p class="mut">Aucun événement pour l\'instant.</p>';}
const evHtml=e=>`<div class="ev"><span class="t">${esc(e.at.replace("T"," ").slice(0,16))}</span><span class="pill">${esc(e.type)}</span><span style="flex:1;min-width:0">${esc(e.text)}${e.rebuilt?' <small class="mut">(reconstitué)</small>':''}</span></div>`;
$("jrtype").onchange=loadJournal;
const ST_SRC={default:"(par défaut)",settings:"(réglage enregistré)",env:"(variable OSINT_DATA_DIR)",cli:"(option --data-dir)"};
async function loadSettings(){try{const d=await J("/api/settings");$("stdir").textContent=d.data_dir;$("stsrc").textContent=ST_SRC[d.source]||"";$("stfile").textContent=d.settings_file;}catch(e){}}
$("stgo").onclick=async()=>{const m=$("stmsg");m.className="";m.textContent="…";
 try{const d=await J("/api/settings/data-dir",{method:"POST",headers:JSONH,body:JSON.stringify({path:$("stpath").value,copy_data:$("stcopy").checked})});
  m.className="s-terminé";m.textContent="Enregistré : "+d.data_dir+(d.copied&&d.copied.length?" (copié : "+d.copied.join(", ")+")":"")+". Ferme puis relance l'application pour l'utiliser."+(d.note?" "+d.note:"");}
 catch(e){m.className="s-erreur";m.textContent=e.message;}};
/* ================= console : tuiles ================= */
let TOOLS=null,DASHAN=null,DASHJR=[],EDIT=false;
const TILE_DEF={
 last:{t:"Dernière analyse",v:"res"},tools:{t:"Outils",v:null},accounts:{t:"Comptes trouvés",v:"res"},reqs:{t:"Demandes",v:"req"},
 leaks:{t:"Fuites connues",v:"leak"},check:{t:"Checklist",v:"ck"},journal:{t:"Activité récente",v:"journal"},cmp:{t:"Comparaison",v:"res"}};
const TILE_IDS=Object.keys(TILE_DEF);
function tileOrder(){const o=(UI.tiles.order||[]).filter(k=>TILE_DEF[k]);return o.concat(TILE_IDS.filter(k=>!o.includes(k)));}
function donutSvg(parts){const r=42,c=2*Math.PI*r;let off=0;const tot=parts.reduce((a,p)=>a+p.v,0);
 if(!tot)return `<svg width="120" height="120" viewBox="0 0 120 120" aria-hidden="true"><circle cx="60" cy="60" r="${r}" fill="none" stroke="var(--line)" stroke-width="18"/><text x="60" y="66" text-anchor="middle" font-size="22" font-weight="700" fill="currentColor">0</text></svg>`;
 return `<svg width="120" height="120" viewBox="0 0 120 120" role="img" aria-label="Comptes par sensibilité">${parts.map(p=>{const len=c*p.v/tot;const el=`<circle cx="60" cy="60" r="${r}" fill="none" stroke="${p.col}" stroke-width="18" stroke-dasharray="${len} ${c-len}" stroke-dashoffset="${-off}" transform="rotate(-90 60 60)"/>`;off+=len;return el;}).join("")}<text x="60" y="66" text-anchor="middle" font-size="22" font-weight="700" fill="currentColor">${tot}</text></svg>`;}
const lastDone=()=>HIST.find(j=>j.state==="terminé");
function tileBody(k){
 if(k==="last"){const j=HIST[0];if(!j)return `<p class="mut">Aucune analyse pour l'instant.</p><div class="row"><button class="pri" data-go="scan">+ Nouvelle analyse</button></div>`;
  return `<dl class="dl"><dt>Date</dt><dd>${new Date(j.created*1000).toLocaleString("fr-FR",{dateStyle:"short",timeStyle:"short"})}</dd><dt>État</dt><dd class="s-${esc(j.state)}">${esc(j.state)}</dd><dt>Cibles</dt><dd>${esc(j.targets.join(", "))}</dd><dt>Résultats</dt><dd>${j.found}</dd></dl>
   <div class="row" style="margin:0"><button class="pri" data-go="scan">+ Nouvelle analyse</button><button onclick="open_('${esc(j.id)}');show('res')">Ouvrir</button></div>`;}
 if(k==="tools"){if(!TOOLS)return `<p class="mut">…</p>`;
  return `<div class="chips">${TOOLS.tools.map(t=>`<span class="chip ${t.ok?"c-ok":"c-ko"}" style="cursor:default"><b>${esc(t.name)}</b>${t.ok?esc(t.version||"présent"):"absent"}</span>`).join("")}<span class="chip ${OLLAMA_OK?"c-ok":"c-off"}" style="cursor:default"><b>Ollama</b>${OLLAMA_OK?"joignable":"non joignable"}</span></div>
   <p class="mut" style="font-size:12px;margin:0">Holehe : une partie des sites bloque les tests, regarde la couverture dans chaque analyse.</p>`;}
 if(k==="accounts"){if(!DASHAN)return `<p class="mut">${lastDone()?"…":"Aucune analyse terminée."}</p>`;
  const n=s=>DASHAN.items.filter(i=>i.sensitivity===s).length;
  const parts=[{l:"élevée",v:n("élevée"),col:"var(--ko)"},{l:"moyenne",v:n("moyenne"),col:"var(--warn)"},{l:"faible",v:n("faible"),col:"var(--acc)"}];
  const s=DASHAN.summary;
  return `<div class="donut">${donutSvg(parts)}<div class="legend">${parts.map(p=>`<span><i style="background:${p.col}"></i>${p.v} sensibilité ${p.l}</span>`).join("")}<span class="mut">${s.by_level["prioritaire"]||0} à traiter en priorité</span></div></div>`;}
 if(k==="reqs"){const items=DASHAN?DASHAN.items.filter(i=>i.level!=="faible").slice(0,12):[];
  const chips=items.map(it=>{const r=findReq(it.site,it.url);const cls=!r?"c-off":r.status==="effacé"?"c-ok":r.status==="refusée"||r.overdue?"c-ko":"c-warn";
   const t=!r?"à demander":r.overdue?"en retard":r.status;
   return r?`<button class="chip ${cls}" data-follow="${esc(r.id)}"><b>${esc(it.site)}</b>${esc(t)}</button>`:`<button class="chip ${cls}" data-mkreq data-site="${esc(it.site)}" data-url="${esc(/^https?:\/\//.test(it.url)?it.url:"")}" data-target="${esc(it.kind==="email"?"à l'adresse email "+it.target:"au pseudo « "+it.target+" »")}"><b>${esc(it.site)}</b>à demander</button>`;});
  const extra=RQ.filter(r=>!items.some(it=>findReq(it.site,it.url)===r)).slice(0,8).map(r=>`<button class="chip ${r.status==="effacé"?"c-ok":r.status==="refusée"||r.overdue?"c-ko":"c-warn"}" data-follow="${esc(r.id)}"><b>${esc(r.site)}</b>${r.overdue?"en retard":esc(r.status)}</button>`);
  const all=chips.concat(extra);const late=RQ.filter(r=>r.overdue).length;
  return all.length?`<div class="chips">${all.join("")}</div><p class="mut" style="font-size:12px;margin:0">Gris : faire la demande · orange : en attente · rouge : en retard ou refusée · vert : effacé.${late?` <b style="color:var(--ko)">${late} en retard.</b>`:""}</p>`:`<p class="mut">Aucune demande et aucun compte prioritaire.</p>`;}
 if(k==="leaks")return `<div class="row" style="margin:0"><span class="big">${LK.length}</span><span class="mut">${LK.length?"dernière notée : "+esc(LK[LK.length-1].service):"aucune fuite notée"}</span></div>
  <div class="row" style="margin:0"><a class="btn" href="/api/leaks/export" download>Exporter</a><button onclick="show('leak');setTimeout(()=>$('lkimpbtn').click(),50)">Importer</button></div>`;
 if(k==="check"){const [n,t]=ckCount(),p=t?Math.round(100*n/t):0;return `<div class="row" style="margin:0"><span class="big">${p}%</span><span class="mut">${n} sur ${t} contrôles</span></div><div class="bar"><i style="width:${p}%;background:var(--ok)"></i></div>`;}
 if(k==="journal")return DASHJR.length?DASHJR.map(evHtml).join(""):`<p class="mut">Aucun événement.</p>`;
 if(k==="cmp")return `<div id="dashcmp"><p class="mut">${lastDone()?"…":"Aucune analyse terminée."}</p></div>`;
 return "";}
function renderTiles(){const hidden=new Set(UI.tiles.hidden||[]),ord=tileOrder();
 $("tiles").classList.toggle("editing",EDIT);
 $("tiles").innerHTML=ord.filter(k=>EDIT||!hidden.has(k)).map((k,i,a)=>{const d=TILE_DEF[k];
  return `<div class="tile${hidden.has(k)?" off":""}" data-tile="${k}" ${EDIT?'draggable="true"':""}><div class="h"><h3>${d.t}</h3>${d.v?`<button class="lnk" data-go="${d.v}">détail</button>`:""}
   <span class="tools"><button data-mv="-1" data-k="${k}" aria-label="Déplacer avant" ${i===0?"disabled":""}>←</button><button data-mv="1" data-k="${k}" aria-label="Déplacer après" ${i===a.length-1?"disabled":""}>→</button><button data-hide="${k}">${hidden.has(k)?"Afficher":"Masquer"}</button></span></div><div class="c">${tileBody(k)}</div></div>`;}).join("");
 if(!EDIT&&!ord.some(k=>!hidden.has(k)))$("tiles").innerHTML=`<p class="mut">Toutes les tuiles sont masquées : « Personnaliser » pour en réafficher.</p>`;
 dashCmp();}
async function dashCmp(){const box=$("dashcmp"),j=lastDone();if(!box||!j)return;
 try{const d=await J(`/api/jobs/${j.id}/compare`);if(!$("dashcmp"))return;
  $("dashcmp").innerHTML=d.previous?`<div class="row" style="margin:0"><span class="pill ${d.new.length?"p-ko":""}">${d.new.length} nouveau(x)</span><span class="pill">${d.gone.length} non retrouvé(s)</span><span class="pill">${d.same} inchangé(s)</span></div><p class="mut" style="font-size:12px;margin:6px 0 0">Par rapport au ${new Date(d.previous.created*1000).toLocaleDateString("fr-FR")}.</p>`:`<p class="mut">Pas encore d'analyse précédente avec les mêmes cibles.</p>`;}catch(e){}}
async function loadDash(){
 await Promise.all([loadHist(),(async()=>{try{LK=(await J("/api/leaks")).leaks||[];}catch(e){}})(),(async()=>{try{TOOLS=await J("/api/status");}catch(e){}})(),
  (async()=>{try{DASHJR=(await J("/api/journal?limit=6")).events||[];}catch(e){}})(),(async()=>{try{RQ=(await J("/api/requests")).requests||[];}catch(e){}})()]);
 const j=lastDone();if(j){try{DASHAN=await J(`/api/jobs/${j.id}/analysis?`+idq());}catch(e){DASHAN=null;}}else DASHAN=null;
 updBadges();if(VIEW==="dash")renderTiles();}
function saveTiles(order,hidden){saveUI({tiles:{order,hidden}});}
$("tiles").addEventListener("click",e=>{const b=e.target.closest("button");if(!b)return;
 if(b.dataset.mv){const o=tileOrder(),i=o.indexOf(b.dataset.k),j=i+(+b.dataset.mv);if(j<0||j>=o.length)return;[o[i],o[j]]=[o[j],o[i]];UI.tiles.order=o;saveTiles(o,UI.tiles.hidden||[]);renderTiles();
  const nb=document.querySelector(`.tile[data-tile="${b.dataset.k}"] [data-mv="${b.dataset.mv}"]`);if(nb&&!nb.disabled)nb.focus();}
 if(b.dataset.hide){const h=new Set(UI.tiles.hidden||[]);h.has(b.dataset.hide)?h.delete(b.dataset.hide):h.add(b.dataset.hide);UI.tiles.hidden=[...h];saveTiles(tileOrder(),UI.tiles.hidden);renderTiles();}});
let DRAG=null;
$("tiles").addEventListener("dragstart",e=>{const t=e.target.closest(".tile");if(!EDIT||!t)return;DRAG=t.dataset.tile;t.classList.add("drag");e.dataTransfer.effectAllowed="move";try{e.dataTransfer.setData("text/plain",DRAG);}catch(_){}});
$("tiles").addEventListener("dragend",e=>{document.querySelectorAll(".tile").forEach(t=>t.classList.remove("drag","over"));DRAG=null;});
$("tiles").addEventListener("dragover",e=>{if(!DRAG)return;const t=e.target.closest(".tile");if(!t)return;e.preventDefault();document.querySelectorAll(".tile.over").forEach(x=>x!==t&&x.classList.remove("over"));if(t.dataset.tile!==DRAG)t.classList.add("over");});
$("tiles").addEventListener("drop",e=>{const t=e.target.closest(".tile");if(!DRAG||!t)return;e.preventDefault();const o=tileOrder().filter(k=>k!==DRAG);o.splice(o.indexOf(t.dataset.tile)+(o.indexOf(t.dataset.tile)>=tileOrder().indexOf(DRAG)?1:0),0,DRAG);
 UI.tiles.order=o;saveTiles(o,UI.tiles.hidden||[]);DRAG=null;renderTiles();});
$("dashedit").onclick=()=>{EDIT=!EDIT;$("dashedit").textContent=EDIT?"Terminer":"Personnaliser";$("dashedit").classList.toggle("pri",EDIT);$("dashhint").hidden=!EDIT;$("dashreset").hidden=!EDIT;renderTiles();};
$("dashreset").onclick=()=>{UI.tiles={order:[],hidden:[]};saveTiles([],[]);renderTiles();};
/* ================= badges du menu ================= */
function updBadges(){const late=RQ.filter(r=>r.overdue).length;
 BADGE={req:late?` <span class="cnt pill p-ko">${late}</span>`:(RQ.length?` <span class="cnt pill">${RQ.length}</span>`:""),leak:LK.length?` <span class="cnt pill">${LK.length}</span>`:""};renderNav();}
/* ================= démarrage ================= */
try{const s=JSON.parse(lsGet("osint_id")||"null");if(s){$("idfirst").value=s[0]||"";$("idlast").value=s[1]||"";}}catch(e){}
try{const e=JSON.parse(lsGet("nm_extra")||"null");if(e){$("nmcity").value=e[0]||"";$("nmjob").value=e[1]||"";}}catch(e){}
["idfirst","idlast","nmcity","nmjob"].forEach(i=>$(i).addEventListener("input",renderNm));
addField("pseudos","pseudo");addField("emails","email@exemple.fr");
renderNm();loadChecks();loadSettings();loadModels();
(async()=>{try{UI=await J("/api/settings/ui");}catch(e){}applyUI();await Promise.all([loadReqs(),loadLeaks(),loadHist()]);show(lsGet("osint_view")||(UI.layout==="console"?"dash":"res"));})();
setInterval(()=>{if(document.hidden)return;if(VIEW==="dash"&&!EDIT)loadDash();if(VIEW==="journal")loadJournal();},20000);
</script></body></html>
"""

# ------------------------------------------------ Relance hebdomadaire (sans interface)
REPORT_DIR = BASE / "rapports_hebdo"


def rescan_cli():
    """Relance la dernière analyse terminée, la compare à la précédente et écrit un rapport.
    Ne contacte personne : aucune demande n'est envoyée, les relances restent à ta main."""
    load_jobs()
    rebuild_journal()
    done = [j for j in JOBS.values() if j.get("state") == "terminé"]
    if not done:
        print("Aucune analyse terminée à relancer : lance-en une d'abord depuis l'interface.")
        return 2
    base = max(done, key=lambda j: j["created"])
    pseudos = [t["value"] for t in base["targets"] if t["kind"] == "pseudo"]
    mails = [t["value"] for t in base["targets"] if t["kind"] == "email"]
    job = new_job(pseudos, mails, base.get("options"), base.get("identity"))
    JOBS[job["id"]] = job
    save_job(job)
    print(f"Relance de l'analyse {base['id']} ({len(pseudos)} pseudo(s), {len(mails)} email(s)) : cela peut durer plusieurs minutes…")
    run_job(job)
    cmp_ = compare_jobs(job, base)
    today = date.today()
    lines = [f"# Audit hebdomadaire du {today.isoformat()}", "",
             f"Analyse {job['id']} : état « {job['state']} », "
             f"{sum(len(t.get('results', [])) for t in job['targets'])} résultat(s). Comparée à l'analyse {base['id']}.", ""]
    lines.append(f"## Nouveaux comptes ({len(cmp_['new'])})")
    lines += [f"- {x['site']} ({x['target']}) {x['url']}" for x in cmp_["new"]] or ["- aucun"]
    lines.append(f"\n## Comptes disparus ({len(cmp_['gone'])})")
    lines += [f"- {x['site']} ({x['target']}) {x['url']}" for x in cmp_["gone"]] or ["- aucun"]
    lines.append(f"\nInchangés : {cmp_['same']}.")
    if job["state"] != "terminé":
        cmp_["caveats"].append(f"l'analyse s'est terminée à l'état « {job['state']} »")
    if cmp_["caveats"]:
        lines.append("\n⚠ Prudence : « disparu » peut seulement vouloir dire « non détecté cette fois » :")
        lines += [f"- {c}" for c in cmp_["caveats"]]
    reqs = [req_view(x) for x in load_reqs()]
    late = [r for r in reqs if r["overdue"]]
    soon = [r for r in reqs if r["days_left"] is not None and 0 <= r["days_left"] <= 7]
    lines.append(f"\n## Demandes en retard ({len(late)})")
    lines += [f"- {r['site']} : échéance {r['due']} dépassée (relance à préparer et à envoyer toi-même)" for r in late] or ["- aucune"]
    lines.append(f"\n## Échéances dans 7 jours ({len(soon)})")
    lines += [f"- {r['site']} : {r['due']}" for r in soon] or ["- aucune"]
    lines.append("\n## Pages des demandes en attente")
    waiting = [r for r in reqs if r.get("url") and r.get("status") in REQ_WAITING][:20]
    for r in waiting:
        lines.append(f"- {r['site']} : {interpret_check(check_page(r['url']))}")
        time.sleep(1)
    if not waiting:
        lines.append("- aucune")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    safe_chmod(REPORT_DIR, 0o700)
    out = REPORT_DIR / f"{today.isoformat()}.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Rapport :", out)
    msg = f"{len(cmp_['new'])} nouveau(x), {len(cmp_['gone'])} disparu(s), {len(late)} demande(s) en retard"
    journal("rapport", f"Relance hebdomadaire : {msg} (rapport {out.name})", job["id"])
    print(msg)
    if shutil.which("notify-send"):
        subprocess.run(["notify-send", "Audit données perso", msg], check=False)
    return 0


def install_timer_windows():
    cmd = quote_cmd(self_cmd_data() + ["--rescan"])
    print("Tâche planifiée hebdomadaire (lundi 09:00). Rien n'est créé tant que tu ne lances pas cette commande")
    print("dans une invite de commandes ou PowerShell :")
    print()
    print(f'  schtasks /Create /TN "audit-donnees-perso rescan" /SC WEEKLY /D MON /ST 09:00 /TR "{cmd.replace(chr(34), chr(92) + chr(34))}"')
    print()
    print('Pour vérifier : schtasks /Query /TN "audit-donnees-perso rescan"')
    print('Pour arrêter  : schtasks /Delete /TN "audit-donnees-perso rescan" /F')
    return 0


def install_timer():
    if IS_WIN:
        return install_timer_windows()
    d = Path.home() / ".config" / "systemd" / "user"
    d.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve()
    (d / "audit-rescan.service").write_text(
        "[Unit]\nDescription=Audit hebdomadaire de mes données perso (audit_donnees_perso)\n\n"
        f"[Service]\nType=oneshot\nExecStart={quote_cmd(self_cmd_data() + ['--rescan'])}\n", encoding="utf-8")
    (d / "audit-rescan.timer").write_text(
        "[Unit]\nDescription=Audit hebdomadaire (lundi 09:00)\n\n"
        "[Timer]\nOnCalendar=Mon *-*-* 09:00:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n", encoding="utf-8")
    print("Fichiers écrits dans", d)
    print("Pour activer (rien n'est activé tant que tu ne le fais pas) :")
    print("  systemctl --user daemon-reload && systemctl --user enable --now audit-rescan.timer")
    print("Pour vérifier : systemctl --user list-timers | grep audit-rescan")
    print("Pour arrêter  : systemctl --user disable --now audit-rescan.timer")
    return 0


# ------------------------------------------------------- Fenêtre native (mode « application »)
HOST, PORT = "127.0.0.1", 8300
URL = f"http://{HOST}:{PORT}/"
BROWSERS = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "microsoft-edge"]
# Icône de l'application (PNG 256 px, illustration GraphicMama-team, licence Pixabay) : favicon de la fenêtre
# et icône du lanceur créé par --install-launcher.
ICON_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAMAAABrrFhUAAADAFBMVEWTopQnJyfc5djGtp1kXFkmJiZBLxycICStoX/hz7nf"
    "z7bb2M4cbUMAlT8A/wBdpoF//3980aOAX0ChXaGdgVe/sZjMoG3QoaHArpnArqHfz7b/8NcUFBQ/Pz8AfwAfqmB/fwBfUDZm"
    "ZmZklnuml3+9sJz/AP//VVX/qlX/qv/FvMHgz7j/8NcAAACllX6pmoPq2cS2ppDXyLECAgLj07xMsnzLuqTDs5vmyLEASSYA"
    "ZzMClEcRFhE4NDLy4s0qJyX8/PxLSEZWVVPe0LiIh4bFqpKWhneijHqHeW55dnRsaGZPQzcBVisBJhOXlpVxZllGOzF0VzUA"
    "dTi3t7YtJBr///8ANhplWlCvh04xqGhTt4Kop6doh5MCi0LX19fHx8fp6OYjHBZGrHa+sJnJKC8AhD2HZzmqqqp/f3+XdUW3"
    "JSo5SU9zlqXFpnhnTCxdeYVMmHMNo1M8UlSrm4MAQx2jfEqKaUb//65uxpe6klasnIQHPCITdkRQaHFhfYmdkHz2589FWmO0"
    "pIv/qqokmlqrm4P/f3/+8dj26M746dBFNBy9f3/26NCLyqn358///39QdmpyGBsxCAoxaUxJiGltk5aR1bEAAACsnISrm4Ow"
    "pIv2584cJCZou4+yookshFY3sXCqqlUjol5VEhS/v3+/v7/XyLDp2sL26M8reVF9YDevnYUBAQExPUL/v78AAAA6iWFWwYhu"
    "qIy2p47XyK/Vxq4CAgIBAQEBAQF9o7OvmorBlVT//wA4l2VEdFq14srBnWjLu6PZyLHYybDj07vq2sI+MBu3p4+2tJPMvKTM"
    "vKXUxKz/AADr28MsRTiTcT61pY7K59js2bvj1Lzk1Lvv2MsYHiFIDA5OY1mDqLO8onyx2sXVx67a2LTj1Lrw3cX68tYkHCFu"
    "iHqMHCGDWzSQuKSwoonFtJ3PvKfMvaTj07zk1b3r3MQkWT1VVVV6zKHEqpDMvKQAAP8A//9GP0OFGx6AbmKTk2quln+mzLqk"
    "1bvGtJvEtJzd0LbiybDt3cWloSN9AAABAHRSTlP/E/+V8q///xErmxT//wH/Av//BP9C/wVe/2SLSsIC/wL/Bf+KJwEDAwP/"
    "2FsA/v7+/v7+/v/+/v/////+/v7+//7+/v7//v/+/v7////+//7///7/Af///////v///////v/+////AwL/////////////"
    "bv///wP//7D//////6//LwP/zQL/FS//BM7/UAL/////////0lGPE4z//0v//wP//wQEsZBv//8tcv8EsP///4+T1TFQjf8T"
    "/wH/////00htjdH/0QwsURgBbf//rf8QrMwR////////MQ1ILRX//////20xFWcpZ0z/A/8NqgEB////Bgv//xPMUw+po8EC"
    "VwAARQxJREFUeNrVvQl8G9d16M2k7Wtf3/69/b1vX9/7vgcMZi40QwJ3MJwRMJzBABgABAEu5gIqpMjIpEVZsiVLsrzIii1b"
    "tmzZcuJ4T5zETtzYjpM4i2OniZO0SZMmafuyp2nTfX3dl6/tO+feGWAAzoAAKFnu2D9JJima5z9nvffcc0dir8Mztf+n9vM/"
    "PfHd73//d3/ns5/9+mu/8FoSnr1J9iRee+2mv3vve3/u7ju+/7U1/pXXXz819Xr8bCOXXfjrr2e/P/W17//OZ7/+CyhyAp5k"
    "x4MfSWQyGfj1tbtueu/dd9zOgT11/dTfawBTtz6Fv6394vc+8/VfkJJMbqn97E1ufxgHAHHXO3/u7tvZN/mp/VN/PwGsPXUG"
    "ft3/23/zkyh7h+RMeniS4U/Cx3DTOzmEqctoDSOXS3r8kX/xey+C8Ntk34lAwn8CEKaemvr7A4D/sL/9H74Owu+VIp8+CHAI"
    "mZvu/uXLpgeXHsAU+q/f/gxKL/V+Igkkuh5k8D6mB1NvdABT6PW+9h9+Uur16gcnwBkwW7jUpnBJAZyBiHfr916UklJ/z94B"
    "CDAG77wDEay9QQFMgdf/7mc+3Lf4AxNoqcGlDIyXDAD+UP/wxUGk798RdjC4C9Xgnqk3GIBbvxSL/fR7pMGfgQn4lnCp/OHI"
    "pXr7Q4k/mCMMMLjpbvA4U28QAPescfHl14+Ah2Bq7Q0AAMP+LsQf2BEGEFwSQ9gtAAh830Hx5aEBDEvAR3BFAdwai33xRSb+"
    "bgkkhyAACN55+26VYGR32v9vP+OLfyV0IJF5213/BbRw6soAAO3/6Q+3xb8iOoB28I92ZQdDAwDN+80XpQ75rwgBbgfDK8HI"
    "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"
)
ICON_PNG = base64.b64decode(ICON_PNG_B64)


def server_alive():
    try:
        with urllib.request.urlopen(URL + "api/checklist", timeout=2) as r:
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


def port_busy():
    with socket.socket() as sk:
        sk.settimeout(1)
        return sk.connect_ex((HOST, PORT)) == 0


def notify(msg):
    if shutil.which("notify-send"):
        subprocess.run(["notify-send", "Audit données perso", msg], check=False)


def browser_candidates():
    """Chemins des navigateurs capables d'ouvrir une fenêtre « application » (--app=)."""
    if IS_WIN:
        roots = [os.environ.get(k) for k in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA")]
        rel = [r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe",
               r"BraveSoftware\Brave-Browser\Application\brave.exe", r"Chromium\Application\chrome.exe"]
        found = [str(Path(r) / x) for x in rel for r in roots if r and (Path(r) / x).exists()]
        return found
    return [shutil.which(b) for b in BROWSERS]


def open_window():
    """Ouvre l'interface dans une fenêtre d'application. Retourne un objet avec wait() ou None."""
    try:
        import webview  # type: ignore  # pywebview, si installé
        class WV:
            def wait(self):
                webview.create_window("Audit de mes données", URL, width=1280, height=900)
                webview.start()
        return WV()
    except Exception:  # noqa: BLE001
        pass
    prof = BASE / ".window-profile"
    for exe in browser_candidates():
        if exe:
            cmd = [exe, f"--app={URL}", f"--user-data-dir={prof}", "--no-first-run", "--no-default-browser-check",
                   "--window-size=1280,900"] + ([] if IS_WIN else ["--class=audit-donnees-perso"])
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            class CH:
                def wait(self):
                    proc.wait()
            return CH()
    return None


def window_mode():
    own = None
    if server_alive():
        print("L'application tourne déjà : ouverture d'une fenêtre.")
    elif port_busy():
        print(f"Le port {PORT} est occupé par autre chose : ferme-le puis relance.")
        notify(f"Port {PORT} occupé : impossible de démarrer.")
        return 1
    else:
        load_jobs()
        rebuild_journal()
        own = uvicorn.Server(uvicorn.Config(app, host=HOST, port=PORT, log_level="warning"))
        threading.Thread(target=own.run, daemon=True).start()
        for _ in range(60):
            if server_alive():
                break
            time.sleep(0.25)
        else:
            print("Le serveur n'a pas démarré.")
            return 1
    w = open_window()
    if w is None:
        print("Aucune fenêtre d'application disponible (Chrome, Chromium, Brave ou Edge) : ouverture dans le navigateur par défaut.")
        if IS_WIN:
            import webbrowser
            webbrowser.open(URL)
        elif shutil.which("xdg-open"):
            subprocess.run(["xdg-open", URL], check=False)
        else:
            print("Ouvre cette adresse dans ton navigateur :", URL)
        if own:
            print("Ctrl+C pour arrêter.")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
        return 0
    w.wait()
    if own:
        busy = lambda: any(j.get("state") in ("running", "queued") for j in JOBS.values())  # noqa: E731
        if busy():
            notify("Fenêtre fermée : l'analyse en cours continue, l'application s'arrêtera à la fin.")
            while busy():
                time.sleep(5)
        own.should_exit = True
        time.sleep(1)
    return 0


def install_launcher_windows():
    """Raccourci dans le menu Démarrer (via PowerShell / WScript.Shell)."""
    menu = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    menu.mkdir(parents=True, exist_ok=True)
    lnk = menu / "Audit données perso.lnk"
    cmd = self_cmd_data() + ["--window"]
    target, args = cmd[0], subprocess.list2cmdline(cmd[1:])
    ps = ("$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:AUDIT_LNK);"
          "$s.TargetPath=$env:AUDIT_TARGET;$s.Arguments=$env:AUDIT_ARGS;"
          "$s.IconLocation=$env:AUDIT_TARGET + ',0';"
          "$s.Description='Audit de mes propres données diffusées';$s.Save()")
    env = dict(os.environ, AUDIT_LNK=str(lnk), AUDIT_TARGET=target, AUDIT_ARGS=args)
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], env=env,
                       capture_output=True, text=True, check=False, creationflags=subprocess.CREATE_NO_WINDOW)
    if r.returncode != 0 or not lnk.exists():
        print("Raccourci non créé :", (r.stderr or r.stdout).strip()[:300])
        return 1
    print("Raccourci écrit :", lnk)
    print("Cherche « Audit données perso » dans le menu Démarrer. Pour le retirer : supprime ce raccourci.")
    return 0


def install_launcher():
    if IS_WIN:
        return install_launcher_windows()
    script = Path(__file__).resolve()
    apps = Path.home() / ".local" / "share" / "applications"
    icons = Path.home() / ".local" / "share" / "icons"
    apps.mkdir(parents=True, exist_ok=True)
    icons.mkdir(parents=True, exist_ok=True)
    icon = icons / "audit-donnees-perso.png"
    icon.write_bytes(ICON_PNG)
    (icons / "audit-donnees-perso.svg").unlink(missing_ok=True)  # ancienne icône (bouclier)
    desk = apps / "audit-donnees-perso.desktop"
    desk.write_text(
        "[Desktop Entry]\nType=Application\nName=Audit données perso\n"
        "Comment=Audit de mes propres données diffusées\n"
        f"Exec={quote_cmd(self_cmd_data() + ['--window'])}\n"
        f"Icon={icon}\nTerminal=false\nCategories=Utility;Security;\nStartupWMClass=audit-donnees-perso\n",
        encoding="utf-8")
    os.chmod(desk, 0o755)
    for old in (apps / "osint-audit.desktop", icons / "osint-audit.svg"):  # lanceur de l'ancien nom
        if old.exists():
            old.unlink()
            print("Ancien lanceur retiré :", old)
    print("Lanceur écrit :", desk)
    print("Cherche « Audit données perso » dans le menu des applications (déconnexion/reconnexion si absent).")
    print("Pour l'épingler : clic droit sur l'icône > Ajouter aux favoris.")
    print("Pour le retirer : supprime ce fichier .desktop.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Audit de mes propres données diffusées")
    ap.add_argument("--rescan", action="store_true", help="relance la dernière analyse, compare et écrit un rapport (sans interface)")
    ap.add_argument("--window", action="store_true", help="ouvre l'application dans sa propre fenêtre (sans onglet de navigateur)")
    ap.add_argument("--install-launcher", action="store_true", help="crée l'icône dans le menu des applications (menu Démarrer sous Windows)")
    ap.add_argument("--install-timer", action="store_true", help="minuteur hebdomadaire : fichiers systemd (utilisateur) sous Linux, commande schtasks sous Windows ; rien n'est activé")
    ap.add_argument("--data-dir", metavar="DOSSIER", help="dossier de données pour ce lancement (sinon OSINT_DATA_DIR, "
                    "puis le réglage de l'interface, puis ~/osint)")
    args = ap.parse_args()
    for stream in (sys.stdout, sys.stderr):  # accents lisibles même dans une console Windows
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    if args.install_launcher:
        sys.exit(install_launcher())
    if args.window:
        sys.exit(window_mode())
    if args.install_timer:
        sys.exit(install_timer())
    if args.rescan:
        sys.exit(rescan_cli())
    load_jobs()
    rebuild_journal()
    print("Données   :", BASE)
    print("Interface : http://127.0.0.1:8300")
    uvicorn.run(app, host="127.0.0.1", port=8300, log_level="warning")


if __name__ == "__main__":
    main()
