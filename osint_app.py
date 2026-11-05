#!/usr/bin/env python3
"""
osint_app.py — interface web locale pour auditer SES PROPRES données diffusées.

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
  python osint_app.py                  # puis ouvrir http://127.0.0.1:8300
  python osint_app.py --window         # fenêtre d'application autonome
  python osint_app.py --install-launcher   # icône dans le menu des applications

Écoute sur 127.0.0.1 UNIQUEMENT (rapports = données perso agrégées).
À utiliser uniquement sur tes propres identifiants.
NON TESTÉ : le format exact des sorties Maigret/Holehe peut varier selon version.
"""
import argparse
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
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

BASE = Path.home() / "osint"
JOBS_DIR = BASE / "jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)
os.chmod(BASE, 0o700)
BIN = Path(sys.executable).parent  # binaires du venv (repli si l'appel par « python -m » est impossible)


def load_config():
    """Réglages facultatifs : ~/osint/config.json, par ex. {"ollama_url": "http://mon-serveur:11434"}."""
    try:
        d = json.loads((BASE / "config.json").read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


# Assistant IA : un Ollama (local par défaut). Priorité : variable OLLAMA_URL > config.json > localhost.
OLLAMA_URL = str(os.environ.get("OLLAMA_URL") or load_config().get("ollama_url") or "http://127.0.0.1:11434").rstrip("/")


def tool_cmd(script, module):
    """Commande pour lancer un outil avec l'interpréteur courant (« python -I -m »), ce qui marche
    aussi bien dans un venv que dans un AppImage. Repli : le script du dossier bin. None si absent."""
    import importlib.util
    if importlib.util.find_spec(module):
        return [sys.executable, "-I", "-m", module]
    exe = BIN / script
    return [str(exe)] if exe.exists() else None


def self_cmd():
    """Commande qui relance cette application (AppImage ou script Python)."""
    ai = os.environ.get("APPIMAGE")
    if ai and Path(ai).exists():
        return [ai]
    return [sys.executable, str(Path(__file__).resolve())]


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


class Out(str):
    """Sortie d'une commande ; .timeout vaut True si la durée maximale a été atteinte."""
    timeout = False


def run_cmd(job, cmd, cwd, max_s=None):
    """Lance une commande, relaie la sortie dans le journal.
    Retourne (code, sortie). Si max_s est dépassé : arrêt propre (SIGTERM puis SIGKILL), sortie.timeout=True."""
    env = dict(os.environ, NO_COLOR="1", PYTHONUNBUFFERED="1")
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env, text=True, errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    PROCS[job["id"]] = proc
    state = {"timeout": False}
    timers = []

    def _kill():
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _term():
        if proc.poll() is None:
            state["timeout"] = True
            log(job, f"Durée maximale atteinte ({max_s / 60:g} min) : arrêt de l'outil, résultats partiels conservés")
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
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
    base = [sys.executable, "-I", "-u", "-c", HOLEHE_WRAPPER, target["value"], "-C"]
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
        if cov["blocked"] / cov["total"] > 0.5:
            add_warn(target, f"couverture faible : {cov['blocked']}/{cov['total']} sites non testables")
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


# ------------------------------------------------------------------ Orchestre
JOB_SLOT = threading.Semaphore(1)  # une seule analyse à la fois (CPU, limites de débit des sites)


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
                t["results"] = run_holehe(job, t, workdir)
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
        c = t.get("coverage")
        if c and c["total"] and c["blocked"] / c["total"] > 0.5:
            plan.append(f"Holehe n'a pas pu tester {c['blocked']}/{c['total']} sites pour {t['value']} : "
                        "« aucun compte » ne prouve rien. Vérifie à la main les sites bloqués (liste dans le rapport).")
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
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
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
                             headers={"Content-Disposition": f"attachment; filename=osint_{job_id}.csv"})


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
    txt("site", 80); txt("url", 500); txt("ref", 80); txt("note", 500)
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
                x.update(upd)
                _fill_sent(x)
                save_reqs(lst)
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
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (osint-perso-audit; verification de ma propre page)"})
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
        c = t.get("coverage") or {}
        if c.get("total") and c.get("blocked", 0) / c["total"] > 0.5:
            notes.append(f"{t['value']} : plus de la moitié des sites Holehe n'ont pas pu être testés")
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
        headers={"User-Agent": "osint-perso-audit (usage personnel)", "Add-Padding": "true"})
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
        d[body.id] = body.done
        tmp = CHECKLIST_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(CHECKLIST_FILE)
    return {"done": d}


@app.get("/api/assistant/models")
def assistant_models():
    try:
        d = ollama_call("/api/tags", None, 8)
        return {"ok": True, "url": OLLAMA_URL, "models": sorted(m["name"] for m in d.get("models", []))}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "url": OLLAMA_URL, "error": f"{type(e).__name__}: {e}"}


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


# ------------------------------------------------------------------------ UI
HTML = r"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit données perso</title>
<style>
:root{--bg:#fff;--fg:#1d2330;--mut:#6b7385;--card:#f4f6fa;--line:#dde2ec;--acc:#2f6fed;--ok:#18a058;--ko:#d03050;--warn:#c98a00}
@media(prefers-color-scheme:dark){:root{--bg:#14171f;--fg:#e6e9f2;--mut:#8f98ad;--card:#1d222d;--line:#2d3444;--acc:#6b9bff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
header{padding:14px 20px;border-bottom:1px solid var(--line)}h1{font-size:18px;margin:0}
main{display:grid;grid-template-columns:360px 1fr;gap:18px;padding:18px;max-width:1500px;margin:auto}
@media(max-width:900px){main{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
h2{font-size:15px;margin:0 0 10px}h3{font-size:14px;margin:16px 0 6px}
input[type=text],input[type=number],textarea{width:100%;padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
.row{display:flex;gap:6px;margin-bottom:6px}.row button{flex:none}
button{padding:7px 12px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);cursor:pointer;font:inherit}
button.pri{background:var(--acc);color:#fff;border-color:var(--acc)}button:disabled{opacity:.5;cursor:default}
label{display:block;margin:6px 0}small,.mut{color:var(--mut)}
.bar{height:10px;background:var(--line);border-radius:6px;overflow:hidden}.bar>i{display:block;height:100%;background:var(--acc);width:0;transition:width .4s}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;border:1px solid var(--line)}
.s-terminé{color:var(--ok)}.s-erreur{color:var(--ko)}.s-en\ cours{color:var(--acc)}.s-annulé,.s-interrompu{color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}a{color:var(--acc)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;max-height:200px;overflow:auto;font-size:12px;margin:8px 0 0;white-space:pre-wrap}
.kv{font-size:12.5px;color:var(--mut)}.kv b{color:var(--fg);font-weight:600}
dialog{border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--fg);width:min(720px,92vw)}
dialog textarea{height:340px;font-family:monospace;font-size:12.5px}
.hist div{padding:5px 0;border-bottom:1px solid var(--line);cursor:pointer;font-size:13px}.hist div:hover{color:var(--acc)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px}
@media(max-width:700px){.kpis{grid-template-columns:repeat(2,1fr)}}
.kpi{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;text-align:center}
.kpi b{display:block;font-size:24px}.kpi span{font-size:12px;color:var(--mut)}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-bottom:8px}
.hb{display:grid;grid-template-columns:130px 1fr 28px;gap:6px;align-items:center;font-size:12.5px;margin:3px 0}
.hbar{height:9px;background:var(--line);border-radius:5px;overflow:hidden}.hbar i{display:block;height:100%;background:var(--acc)}
.ai{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0;background:var(--bg)}
.ai.prio{border-left-color:var(--ko)}.ai.verif{border-left-color:var(--warn)}.ai.faible{border-left-color:var(--ok)}
.ai p{margin:6px 0;font-size:13.5px}
.badge{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:9px;border:1px solid var(--line);margin:0 4px 4px 0;color:var(--mut)}
.badge.hot{color:var(--ko);border-color:var(--ko)}
.chat .u,.chat .a{padding:8px 10px;border-radius:8px;margin:6px 0;white-space:pre-wrap;font-size:13.5px}
.chat .u{background:var(--bg);border:1px solid var(--line)}.chat .a{background:var(--card);border:1px solid var(--acc)}
details summary{cursor:pointer;color:var(--mut);margin:8px 0}
.ck label{display:flex;gap:8px;align-items:flex-start;margin:6px 0;font-size:13.5px}.ck input{margin-top:3px}
.ck label.dn span{text-decoration:line-through;color:var(--mut)}
</style></head><body>
<header><h1>Audit de mes données diffusées <small>— local, 127.0.0.1</small></h1></header>
<main>
<section>
  <div class="card">
    <h2>Qui suis-je ? <small>(optionnel, reste local)</small></h2>
    <div class="row"><input type="text" id="idfirst" placeholder="Prénom" oninput="idChanged()"><input type="text" id="idlast" placeholder="Nom" oninput="idChanged()"></div>
    <small>Sert à estimer si un profil trouvé est le tien (comparaison avec le nom affiché sur le profil).</small>
  </div>
  <div class="card">
    <h2>Pseudos</h2><div id="pseudos"></div>
    <button onclick="addField('pseudos','pseudo')">+ pseudo</button>
    <h2 style="margin-top:14px">Adresses email</h2><div id="emails"></div>
    <button onclick="addField('emails','email@exemple.fr')">+ email</button>
  </div>
  <div class="card">
    <h2>Options Maigret</h2>
    <label><input type="checkbox" id="allsites"> Tous les sites (long, plusieurs milliers)</label>
    <label>Top sites : <input type="number" id="top" value="500" min="50" max="3000" style="width:90px"></label>
    <label>Timeout par site (s) : <input type="number" id="timeout" value="20" min="5" max="120" style="width:90px"></label>
    <label>Durée max par outil (min) : <input type="number" id="maxmin" value="20" min="2" max="180" style="width:90px"></label>
    <label><input type="checkbox" id="sherlock" checked> Ajouter Sherlock (pseudos, ~400 sites, doublons fusionnés)</label>
    <label><input type="checkbox" id="nsfw"> Sherlock : inclure sites adultes (--nsfw)</label>
    <small>Variantes : <b>franck{?}dupont</b> teste franck_dupont, franck-dupont, franck.dupont (Sherlock seul, sans Maigret).<br>
    Holehe : sites où l'email a un compte (méthode "mot de passe oublié").</small>
  </div>
  <button class="pri" id="go" onclick="start()" style="width:100%">Lancer l'analyse</button>
  <p><small>Uniquement tes propres identifiants.</small></p>
  <div class="card hist"><h2>Historique</h2><div id="hist"></div></div>
</section>
<section>
  <div id="empty" class="card mut">Aucune analyse affichée. Lance-en une ou clique l'historique.</div>
  <div id="view" style="display:none">
    <div class="card">
      <h2>Suivi <span id="state" class="pill"></span></h2>
      <div class="bar"><i id="pbar"></i></div>
      <p class="mut" id="ptxt"></p>
      <div id="tlist"></div>
      <div class="row"><button id="cancel" onclick="cancelJob()">Annuler</button>
        <a id="csv" href="#"><button>Export CSV</button></a>
        <a id="json" href="#" target="_blank"><button>JSON brut</button></a>
        <button id="del" onclick="delJob()">Supprimer</button></div>
      <pre id="log"></pre>
    </div>
    <div id="an" style="display:none">
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
      <div class="card"><h2>Assistant</h2>
        <p class="mut" style="font-size:12.5px;margin-top:0" id="asinfo"></p>
        <div class="row"><select id="asmodel" style="flex:1;padding:7px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg)"></select><button onclick="loadModels()">↻</button></div>
        <div class="chat" id="aschat"></div>
        <div class="row"><textarea id="asq" rows="2" placeholder="Ex : Que veut dire « possible » ? Quel compte supprimer en premier ?"></textarea><button class="pri" onclick="ask()">Demander</button></div>
      </div>
    </div>
    <div class="card"><h2>Rapport site par site</h2>
      <input type="text" id="filter" placeholder="Filtrer (site, cible, info…)" oninput="renderResults()">
      <p class="mut" style="font-size:13px">Ce qui est affiché = ce qui est <b>détectable de l'extérieur</b> (compte existant, infos de profil publiques).
      Ce que chaque site détient réellement en interne ne se voit pas d'ici : bouton « Demande RGPD » pour le réclamer (art. 15), ou demander l'effacement (art. 17).</p>
      <div id="results"></div>
    </div>
  </div>
  <div class="card" id="rq"><h2 id="rqhead" style="cursor:pointer;display:flex;justify-content:space-between;align-items:center;gap:10px" title="Afficher / réduire"><span>Suivi des demandes <small>— effacement / accès (RGPD), échéances, relances</small></span><span id="rqtog" class="mut" style="font-size:13px;white-space:nowrap">▾ réduire</span></h2>
    <div id="rqbody">
     <div class="row" style="flex-wrap:wrap;gap:8px"><input type="text" id="rqsite" placeholder="site / organisme" style="flex:1;min-width:160px"><input type="text" id="rqurl" placeholder="lien de la page concernée (https://…)" style="flex:2;min-width:220px"></div>
     <div class="row" style="flex-wrap:wrap;gap:8px"><select id="rqkind" title="Suppression à la source ou déréférencement d'un moteur de recherche"><option>source</option><option>déréférencement</option></select><select id="rqstatus"><option>à envoyer</option><option>envoyée</option><option>relancée</option><option>réponse reçue</option><option>effacé</option><option>refusée</option></select><input type="date" id="rqsent" title="Date d'envoi" style="width:auto"><input type="text" id="rqref" placeholder="n° de dossier" style="flex:1;min-width:110px"><input type="text" id="rqnote" placeholder="note" style="flex:2;min-width:140px"><button id="rqadd">Ajouter</button></div>
     <p id="rqerr" class="s-erreur" style="margin:6px 0 0"></p>
     <div id="rqlist"></div>
     <p class="mut" style="font-size:12px"><b>Source</b> = la page est supprimée chez l'éditeur ; <b>déréférencement</b> = le résultat disparaît d'un moteur de recherche, la page existe toujours. L'échéance est calculée à 1 mois après l'envoi (art. 12.3 du RGPD), prolongeable jusqu'à 3 mois si la demande est complexe. L'app ne contacte personne : tu envoies toi-même, garde les captures, les accusés de réception et les numéros de dossier.</p>
    </div></div>
  <div class="card" id="nm"><h2 id="nmhead" style="cursor:pointer;display:flex;justify-content:space-between;align-items:center;gap:10px" title="Afficher / réduire"><span>Recherche par nom <small>— liens à ouvrir toi-même</small></span><span id="nmtog" class="mut" style="font-size:13px;white-space:nowrap">▾ réduire</span></h2>
    <div id="nmbody">
     <div class="row" style="flex-wrap:wrap;gap:8px"><input type="text" id="nmcity" placeholder="ville (facultatif : aide à écarter les homonymes)" style="flex:1;min-width:200px"><input type="text" id="nmjob" placeholder="métier / employeur (facultatif)" style="flex:1;min-width:200px"></div>
     <p class="mut" style="font-size:13px">Utilise le prénom et le nom de « Qui suis-je ? ». Chaque lien lance une recherche sur le moteur (Google par défaut) : ton nom lui est donc transmis. N'ouvre que ce que tu veux. Ce sont des recherches, pas des preuves : ouvre chaque résultat et vérifie qu'il s'agit bien de toi.</p>
     <div id="nmlinks"></div>
    </div></div>
  <div class="card" id="lk"><h2 id="lkhead" style="cursor:pointer;display:flex;justify-content:space-between;align-items:center;gap:10px" title="Afficher / réduire"><span>Fuites connues <small>— à noter à la main (ex. compte gratuit haveibeenpwned.com)</small></span><span id="lktog" class="mut" style="font-size:13px;white-space:nowrap">▾ réduire</span></h2>
    <div id="lkbody">
     <div class="row" style="flex-wrap:wrap;gap:8px"><input type="text" id="lkaddr" placeholder="adresse email concernée" style="flex:2;min-width:180px"><input type="text" id="lksvc" placeholder="service / site (ex. Bouygues Télécom)" style="flex:2;min-width:180px"><input type="text" id="lkdate" placeholder="date (ex. août 2025)" style="flex:1;min-width:120px"></div>
     <div class="row" style="margin-top:8px"><input type="text" id="lkdata" placeholder="données exposées, copiées depuis « Détails » (ex. numéros de compte bancaire, dates de naissance)" style="flex:1"><button id="lkadd">Ajouter</button></div>
     <p id="lkerr" class="s-erreur" style="margin:6px 0 0"></p>
     <div id="lklist"></div>
     <p class="mut" style="font-size:12px">Saisie manuelle : l'app ne se connecte pas à HIBP. Les conseils viennent de mots-clés dans les données exposées ; ils ne remplacent pas la lecture de la fiche de la fuite.</p>
    </div></div>
  <div class="card" id="pw"><h2 id="pwhead" style="cursor:pointer;display:flex;justify-content:space-between;align-items:center;gap:10px" title="Afficher / réduire"><span>Mot de passe compromis ? <small>— Pwned Passwords</small></span><span id="pwtog" class="mut" style="font-size:13px;white-space:nowrap">▾ réduire</span></h2>
    <div id="pwbody">
     <p class="mut" style="font-size:13px">Le mot de passe est transformé en empreinte SHA-1 <b>dans ton navigateur</b>. Seuls 5 caractères de cette empreinte partent vers Pwned Passwords (méthode k-anonymat) ; le mot de passe n'est ni envoyé ni enregistré.</p>
     <div class="row"><input type="password" id="pwin" placeholder="mot de passe à tester" autocomplete="off" spellcheck="false" style="flex:1"><button id="pweye" type="button" title="Afficher / masquer la saisie" aria-label="Afficher le mot de passe" aria-pressed="false" style="min-width:42px">👁</button><button id="pwgo">Tester</button></div>
     <p id="pwres" style="margin:10px 0 0"></p>
     <p class="mut" style="font-size:12px">« Trouvé » = ce mot de passe figure dans des fuites connues : ne l'utilise plus nulle part. « Non trouvé » ne prouve pas qu'il est sûr.</p>
    </div></div>
  <div class="card ck" id="ck"><h2 id="ckhead" style="cursor:pointer;display:flex;justify-content:space-between;align-items:center;gap:10px" title="Afficher / réduire"><span>À faire à la main <small>— coche au fur et à mesure (enregistré sur ce PC)</small></span><span id="cktog" class="mut" style="font-size:13px;white-space:nowrap">▾ réduire</span></h2>
    <div class="bar"><i id="ckbar"></i></div><p class="mut" id="cktxt"></p><div id="ckbody"><div id="cklist"></div>
    <p class="mut" style="font-size:12px">Liens écrits de mémoire, non vérifiés un par un : si une page a changé, cherche le nom du service.</p></div>
  </div>
</section></main>
<dialog id="dlg"><h2 id="dtitle"></h2><textarea id="dtext" readonly></textarea>
<div class="row" style="margin-top:8px"><button onclick="copyD()">Copier</button><button onclick="dlg.close()">Fermer</button></div></dialog>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let cur=null,timer=null,job=null;
const dlg=$("dlg");
function addField(box,ph){const d=document.createElement("div");d.className="row";
 d.innerHTML=`<input type="text" placeholder="${ph}"><button onclick="this.parentNode.remove()">×</button>`;$(box).appendChild(d);d.firstChild.focus();}
const vals=box=>[...$(box).querySelectorAll("input")].map(i=>i.value.trim()).filter(Boolean);
async function start(){
 const body={pseudos:vals("pseudos"),emails:vals("emails"),options:{all_sites:$("allsites").checked,top_sites:+$("top").value,timeout:+$("timeout").value,max_min:+$("maxmin").value,sherlock:$("sherlock").checked,nsfw:$("nsfw").checked},identity:{first:$("idfirst").value.trim(),last:$("idlast").value.trim()}};
 $("go").disabled=true;
 try{const r=await fetch("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const j=await r.json(); if(!r.ok){alert(j.detail||"erreur");return;} open_(j.id);}
 finally{$("go").disabled=false;}
}
function open_(id){cur=id;$("empty").style.display="none";$("view").style.display="block";clearInterval(timer);poll();timer=setInterval(poll,2000);}
async function poll(){
 if(!cur)return; const r=await fetch("/api/jobs/"+cur); if(!r.ok)return; job=await r.json(); render(); loadHist();
 if(["terminé","annulé","interrompu"].includes(job.state)) clearInterval(timer);
}
function render(){
 const n=job.targets.length;
 // cible en cours : avancement estimé au temps écoulé (les outils n'exposent pas de vrai %), plafonné à 95 %
 let part=0;const now=Date.now()/1000,mm=((job.options&&job.options.max_min)||20)*60;
 for(const t of job.targets){if(t.status==="en cours"&&t.started){const exp=t.kind==="email"?180:mm;part+=Math.min(.95,(now-t.started)/exp);}}
 const pct=n?Math.min(100,Math.round(100*(job.done+part)/n)):0,est=part>0?" · estimation selon le temps écoulé":"";
 $("pbar").style.width=pct+"%";$("ptxt").textContent=`${job.done}/${n} cibles traitées (${pct}%${est})`+idleTxt();
 $("state").textContent=job.state;$("state").className="pill s-"+job.state;
 $("tlist").innerHTML=job.targets.map(t=>`<div class="row" style="justify-content:space-between"><span>${esc(t.kind)} · <b>${esc(t.value)}</b></span>
  <span><span class="s-${esc(t.status)}">${esc(t.status)}</span> · ${(t.results||[]).length} résultat(s)${t.error?` · <span class="s-erreur">${esc(t.error)}</span>`:""}${t.warn?` · <span class="s-annulé">${esc(t.warn)}</span>`:""}${t.coverage&&!t.warn?` · couverture ${t.coverage.total-t.coverage.blocked}/${t.coverage.total}`:""}${durTxt(t)}</span></div>`).join("");
 const lg=$("log"),atEnd=lg.scrollTop+lg.clientHeight>=lg.scrollHeight-20;
 lg.textContent=job.log.slice(-120).join("\n");if(atEnd)lg.scrollTop=lg.scrollHeight;
 $("cancel").disabled=!["running","queued"].includes(job.state);$("del").disabled=["running","queued"].includes(job.state);
 $("csv").href=`/api/jobs/${cur}/export.csv`;$("json").href=`/api/jobs/${cur}`;
 renderResults();maybeAnalysis();
}
function renderResults(){
 if(!job)return;const f=$("filter").value.toLowerCase();let h="";
 for(const t of job.targets){
  const rows=(t.results||[]).filter(r=>!f||JSON.stringify([t.value,r]).toLowerCase().includes(f));
  h+=`<h3>${esc(t.kind)} : ${esc(t.value)} <small>(${rows.length} / ${(t.results||[]).length})</small></h3>`;
  if(t.coverage&&t.coverage.total){const c=t.coverage,ok=c.total-c.blocked,pct=Math.round(100*ok/c.total);
   h+=`<div class="card" style="margin:6px 0"><b>Couverture Holehe</b> : ${ok}/${c.total} sites testés avec succès (${pct} %)
    <div class="bar" style="margin:6px 0"><i style="width:${pct}%;background:${pct<50?"var(--ko)":"var(--ok)"}"></i></div>
    <span class="mut" style="font-size:12.5px">${c.used} compte(s) trouvé(s), ${c.unused} site(s) sans compte, <b>${c.blocked} non testable(s)</b>. « Aucun compte » ne prouve rien pour les sites bloqués.</span>
    ${c.blocked?`<details><summary>${c.blocked} site(s) bloqué(s) à vérifier à la main</summary>${c.blocked_sites.map(s=>`<a class="badge" href="https://${esc(s)}" target="_blank" rel="noopener noreferrer">${esc(s)}</a>`).join(" ")}</details>`:""}</div>`;}
  if(!rows.length){h+=`<p class="mut">${t.status==="terminé"?(t.coverage&&t.coverage.blocked?"Aucun compte trouvé sur les sites testables.":"Rien trouvé."):"—"}</p>`;continue;}
  h+=`<table><tr><th>Site</th><th>Source</th><th>Infos publiques détectées</th><th></th></tr>`;
  rows.forEach((r,i)=>{
   const kv=Object.entries(r.infos||{}).map(([k,v])=>`<div class="kv"><b>${esc(k)}</b> : ${esc(v)}</div>`).join("")||`<span class="mut">compte détecté, pas de détail public</span>`;
   const safe=/^https?:\/\//.test(r.url);
   h+=`<tr><td>${safe?`<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.site)}</a>`:esc(r.site)}<br><small>${esc((r.tags||[]).join(", "))}</small></td>
    <td>${esc(r.source)}</td><td>${kv}</td>
    <td><button onclick='rgpd(${JSON.stringify(job.targets.indexOf(t))},${JSON.stringify((t.results||[]).indexOf(r))})'>Demande RGPD</button></td></tr>`;});
  h+="</table>";}
 $("results").innerHTML=h||"";
}
function rgpd(ti,ri){
 const t=job.targets[ti],r=t.results[ri],id=t.kind==="email"?`l'adresse email ${t.value}`:`le pseudo « ${t.value} »`;
 $("dtitle").textContent="Demande RGPD — "+r.site;
 $("dtext").value=`Objet : Demande d'accès à mes données personnelles (article 15 du RGPD)

Madame, Monsieur,

Je suis titulaire d'un compte (ou d'une inscription) sur ${r.site}, associé à ${id}.

Conformément à l'article 15 du RGPD, je vous demande de me communiquer :
- la confirmation que vous traitez des données me concernant ;
- une copie de l'ensemble de ces données ;
- les finalités du traitement, les catégories de données, les destinataires (y compris hors UE) ;
- la durée de conservation prévue ;
- l'origine des données qui n'auraient pas été collectées auprès de moi.

[OPTIONNEL — à garder si tu veux supprimer]
Conformément à l'article 17 du RGPD, je demande en outre l'effacement de mon compte et de toutes les données associées, ainsi que la notification de cet effacement aux tiers destinataires.

Vous disposez d'un mois pour répondre (article 12.3 du RGPD). Si une pièce d'identité est nécessaire, merci de m'indiquer le moyen sécurisé de vous la transmettre. À défaut de réponse, je saisirai la CNIL.

Cordialement,
[Prénom Nom]
[Date]

À envoyer au DPO / contact « vie privée » du site (voir mentions légales ou politique de confidentialité).`;
 dlg.showModal();
}
function copyD(){navigator.clipboard.writeText($("dtext").value);}
async function cancelJob(){if(cur)await fetch(`/api/jobs/${cur}/cancel`,{method:"POST"});}
async function loadHist(){
 const r=await fetch("/api/jobs");const l=await r.json();
 $("hist").innerHTML=l.map(j=>`<div onclick="open_('${esc(j.id)}')">${new Date(j.created*1000).toLocaleString("fr-FR")} · <span class="s-${esc(j.state)}">${esc(j.state)}</span> · ${j.found} résultat(s)<br><small>${esc(j.targets.join(", "))}</small></div>`).join("")||`<span class="mut">vide</span>`;
}
const fmt=s=>{s=Math.max(0,Math.round(s));return Math.floor(s/60)+":"+String(s%60).padStart(2,"0");};
const nowS=()=>Date.now()/1000;
function durTxt(t){if(!t.started)return"";
 if(t.finished)return` · durée ${fmt(t.finished-t.started)}`;
 return t.status==="en cours"?` · ${fmt(nowS()-t.started)} écoulées`:"";}
function idleTxt(){if(!job||job.state!=="running"||!job.last_activity)return"";
 const s=nowS()-job.last_activity;
 return` · dernière activité il y a ${fmt(s)}`+(s>120?" (silence normal : Maigret n'affiche que les comptes trouvés ; l'outil est arrêté tout seul à la durée max)":"");}
async function delJob(){if(!cur||!confirm("Supprimer définitivement cette analyse et ses fichiers ?"))return;
 const r=await fetch(`/api/jobs/${cur}`,{method:"DELETE"});const j=await r.json().catch(()=>({}));
 if(!r.ok){alert(j.detail||"erreur");return;}
 clearInterval(timer);cur=null;job=null;anFor=null;AN=null;$("view").style.display="none";$("an").style.display="none";$("empty").style.display="block";loadHist();}
let anFor=null,anTimer=null,asking=false,AN=null;const chat=[];
function maybeAnalysis(){if(!job||!["terminé","annulé","interrompu"].includes(job.state))return;if(anFor===cur)return;anFor=cur;chat.length=0;$("aschat").innerHTML="";loadAnalysis();loadCompare();}
const idq=()=>"first="+encodeURIComponent($("idfirst").value.trim())+"&last="+encodeURIComponent($("idlast").value.trim());
async function loadAnalysis(){if(!cur)return;const r=await fetch(`/api/jobs/${cur}/analysis?`+idq());if(!r.ok)return;AN=await r.json();renderAnalysis();loadModels();}
function idChanged(){try{localStorage.setItem("osint_id",JSON.stringify([$("idfirst").value,$("idlast").value]))}catch(e){}
 clearTimeout(anTimer);anTimer=setTimeout(()=>{if(anFor===cur&&cur)loadAnalysis()},600);}
function bars(o){const e=Object.entries(o||{}).sort((x,y)=>y[1]-x[1]);const m=Math.max(1,...e.map(x=>x[1]));
 return e.map(([k,v])=>`<div class="hb"><span>${esc(k)}</span><div class="hbar"><i style="width:${Math.round(100*v/m)}%"></i></div><b>${v}</b></div>`).join("")||`<span class="mut">—</span>`;}
function card(it,i){const safe=/^https?:\/\//.test(it.url);
 const hot=it.level==="prioritaire";
 return `<div class="ai ${esc(it.css)}"><div class="row" style="justify-content:space-between"><b>${safe?`<a href="${esc(it.url)}" target="_blank" rel="noopener noreferrer">${esc(it.site)}</a>`:esc(it.site)}</b><span class="pill">${esc(it.level)}</span></div>
 <div><span class="badge">${esc(it.category)}</span><span class="badge${it.sensitivity==="élevée"?" hot":""}">sensibilité ${esc(it.sensitivity)}</span><span class="badge${hot?" hot":""}">correspondance : ${esc(it.match_label)}</span><span class="badge">${esc(it.kind)} ${esc(it.target)}</span><span class="badge">${esc(it.source)}</span></div>
 <p>${esc(it.explain)}</p><p><b>À faire :</b> ${esc(it.action)}</p>
 <div>${it.fields.map(f=>`<span class="badge${it.risky.includes(f)?" hot":""}">${esc(f)}</span>`).join("")}</div>
 <div class="row"><button onclick="askAbout(${i})">Demander à l'assistant</button><button onclick="newReq(${i})">Suivre une demande</button></div></div>`;}
function renderAnalysis(){if(!AN)return;const s=AN.summary;$("an").style.display="block";
 $("kpis").innerHTML=[["Comptes détectés",s.total],["À traiter en priorité",s.by_level["prioritaire"]||0],["À vérifier",s.by_level["à vérifier"]||0],["Catégories sensibles",s.sensitive]]
  .map(([l,v])=>`<div class="kpi"><b>${v}</b><span>${l}</span></div>`).join("");
 $("ch_cat").innerHTML=bars(s.by_category);$("ch_match").innerHTML=bars(s.by_match);$("ch_fields").innerHTML=bars(s.exposed_fields);
 $("plan").innerHTML=s.plan.map(x=>`<li>${esc(x)}</li>`).join("");
 const main=[],low=[];AN.items.forEach((it,i)=>(it.level==="faible"?low:main).push(card(it,i)));
 $("anitems").innerHTML=(main.join("")||`<p class="mut">Aucun compte prioritaire ou à vérifier.</p>`)+(low.length?`<details><summary>${low.length} compte(s) à faible priorité</summary>${low.join("")}</details>`:"");}
async function loadModels(){let d;try{d=await (await fetch("/api/assistant/models")).json();}catch(e){d={ok:false,error:String(e)}}
 const sel=$("asmodel"),prev=sel.value;
 if(d.ok&&d.models.length){sel.innerHTML=d.models.map(m=>`<option>${esc(m)}</option>`).join("");if(d.models.includes(prev))sel.value=prev;
  $("asinfo").textContent=`Assistant IA sur ton serveur Ollama (${d.url}) : rien n'est envoyé dans le cloud. Il explique les résultats ci-dessus et peut se tromper.`;}
 else{sel.innerHTML="";$("asinfo").textContent=`Assistant indisponible : Ollama injoignable (${d.url}). ${d.error||""} Définis OLLAMA_URL si l'adresse est différente.`;}}
function addMsg(c,t){const d=document.createElement("div");d.className=c;d.textContent=t;$("aschat").appendChild(d);d.scrollIntoView({block:"nearest"});return d;}
function askAbout(i){const it=AN.items[i];ask(`Explique-moi le résultat « ${it.site} » (${it.url}) : que signifie-t-il pour moi et que dois-je faire ?`);}
async function ask(q){q=q||$("asq").value.trim();if(!q||asking||!cur)return;const model=$("asmodel").value;
 if(!model){addMsg("a","Aucun modèle disponible : Ollama est injoignable.");return;}
 asking=true;$("asq").value="";addMsg("u",q);const w=addMsg("a","… réflexion en cours (peut durer une minute)");
 try{const r=await fetch(`/api/jobs/${cur}/assistant`,{method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({question:q,model,history:chat.slice(-6),first:$("idfirst").value.trim(),last:$("idlast").value.trim()})});
  const j=await r.json();const t=r.ok?j.answer:"Erreur : "+(j.detail||r.status);w.textContent=t;
  if(r.ok)chat.push({role:"user",content:q},{role:"assistant",content:t});}
 catch(e){w.textContent="Erreur : "+e;}finally{asking=false;}}
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
  ["old","Supprimer les comptes inutilisés trouvés par l'analyse (carte « Que faire ? »)."],
  ["alias","Utiliser un alias d'email différent par nouveau site (SimpleLogin, addy.io…) pour repérer qui fuit ton adresse.","https://simplelogin.io"]]},
 {g:"Demander et surveiller",i:[
  ["rgpd","Envoyer les demandes RGPD (accès / effacement) pour les comptes prioritaires, via le bouton du rapport."],
  ["rgpd1m","Noter la date d'envoi : le site a un mois pour répondre. Sans réponse, saisir la CNIL.","https://www.cnil.fr"],
  ["bank","Surveiller les relevés bancaires et les alertes de connexion."],
  ["phish","Rester méfiant sur les mails ou SMS qui citent tes données (hameçonnage)."],
  ["cyber","En cas de problème : cybermalveillance.gouv.fr (assistance), signal-spam.fr (spam).","https://www.cybermalveillance.gouv.fr"]]}];
let ckDone={};
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
 finally{$("pwin").value="";pwShow(false);}
}
async function loadLeaks(){let L=[];try{L=(await (await fetch("/api/leaks")).json()).leaks||[];}catch(e){}
 $("lklist").innerHTML=L.length?L.map(x=>`<div style="border-top:1px solid var(--line);padding:10px 0"><div class="row" style="justify-content:space-between"><span><b>${esc(x.service)}</b>${x.date?` · ${esc(x.date)}`:""}${x.address?` · <span class="mut">${esc(x.address)}</span>`:""}</span><button onclick="delLeak('${esc(x.id)}')" title="Supprimer cette ligne">×</button></div>${x.data?`<div class="mut" style="font-size:13px">Données : ${esc(x.data)}</div>`:""}<ul style="margin:6px 0 0 18px;font-size:13px">${x.advice.map(a=>`<li>${esc(a)}</li>`).join("")}</ul></div>`).join(""):`<p class="mut" style="font-size:13px">Aucune fuite notée.</p>`;}
async function addLeak(){$("lkerr").textContent="";const b={address:$("lkaddr").value,service:$("lksvc").value,date:$("lkdate").value,data:$("lkdata").value};
 if(!b.service.trim()){$("lkerr").textContent="Indique le service ou le site.";return;}
 const r=await fetch("/api/leaks",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});
 if(!r.ok){let d="";try{d=(await r.json()).detail}catch(e){}$("lkerr").textContent=d||"Erreur "+r.status;return;}
 ["lksvc","lkdate","lkdata"].forEach(i=>$(i).value="");await loadLeaks();if(cur)loadAnalysis();}
async function delLeak(id){if(!confirm("Supprimer cette fuite de la liste ?"))return;await fetch("/api/leaks/"+id,{method:"DELETE"});await loadLeaks();if(cur)loadAnalysis();}
$("lkadd").onclick=addLeak;$("lkdata").addEventListener("keydown",e=>{if(e.key==="Enter")addLeak();});
function setLk(open){$("lkbody").style.display=open?"block":"none";$("lktog").textContent=open?"▾ réduire":"▸ afficher";try{localStorage.setItem("lkopen",open?"1":"0");}catch(e){}}
$("lkhead").onclick=()=>setLk($("lkbody").style.display==="none");
try{if(localStorage.getItem("lkopen")==="0")setLk(false);}catch(e){}
loadLeaks();
function mkCollapse(h,b,t,key){const set=o=>{$(b).style.display=o?"block":"none";$(t).textContent=o?"▾ réduire":"▸ afficher";try{localStorage.setItem(key,o?"1":"0");}catch(e){}};
 $(h).onclick=()=>set($(b).style.display==="none");try{if(localStorage.getItem(key)==="0")set(false);}catch(e){}return set;}
const setRq=mkCollapse("rqhead","rqbody","rqtog","rqopen"),setNm=mkCollapse("nmhead","nmbody","nmtog","nmopen");
// ---- suivi des demandes
let RQ=[];
const frd=iso=>{if(!iso)return"";const [y,m,d]=iso.split("-");return `${d}/${m}/${y}`;};
const rqWaiting=r=>r.status==="envoyée"||r.status==="relancée";
async function loadReqs(){try{RQ=(await (await fetch("/api/requests")).json()).requests||[];}catch(e){RQ=[];}renderReqs();}
function dueBadge(r){if(!r.due||!rqWaiting(r))return"";
 if(r.overdue)return `<span class="badge hot">en retard de ${-r.days_left} j (échéance ${frd(r.due)})</span>`;
 return `<span class="badge">échéance dans ${r.days_left} j (${frd(r.due)})</span>`;}
function renderReqs(){const sel=(r)=>["à envoyer","envoyée","relancée","réponse reçue","effacé","refusée"].map(o=>`<option${o===r.status?" selected":""}>${o}</option>`).join("");
 $("rqlist").innerHTML=RQ.length?RQ.map(r=>{const safe=/^https?:\/\//.test(r.url||"");
  return `<div style="border-top:1px solid var(--line);padding:10px 0"><div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:8px"><span><b>${safe?`<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.site)}</a>`:esc(r.site)}</b> <span class="badge">${esc(r.kind)}</span> ${dueBadge(r)}</span>
   <span class="row" style="gap:6px;flex-wrap:wrap;margin:0"><select onchange="updReq('${esc(r.id)}','status',this.value)">${sel(r)}</select><input type="date" value="${esc(r.sent||"")}" title="Date d'envoi" style="width:auto" onchange="updReq('${esc(r.id)}','sent',this.value)"><button onclick="delReq('${esc(r.id)}')" title="Supprimer cette demande">×</button></span></div>
   <div class="row" style="flex-wrap:wrap;gap:8px"><input type="text" value="${esc(r.ref||"")}" placeholder="n° de dossier" style="flex:1;min-width:110px" onchange="updReq('${esc(r.id)}','ref',this.value)"><input type="text" value="${esc(r.note||"")}" placeholder="note" style="flex:3;min-width:160px" onchange="updReq('${esc(r.id)}','note',this.value)"></div>
   <div class="row" style="flex-wrap:wrap;gap:8px"><button onclick="relance('${esc(r.id)}')">Texte de relance</button>${safe?`<button onclick="checkReq('${esc(r.id)}')">Vérifier la page</button>`:""}${r.last_check?`<span class="mut" style="font-size:12.5px;align-self:center">vérifié le ${esc(r.last_check.at)} : ${esc(r.last_check.text)}</span>`:""}</div></div>`;}).join("")
  :`<p class="mut" style="font-size:13px">Aucune demande suivie.</p>`;}
async function reqCall(method,url,body){const r=await fetch(url,{method,headers:{"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined});
 if(!r.ok){let d="";try{d=(await r.json()).detail}catch(e){}$("rqerr").textContent=d||"Erreur "+r.status;return null;}$("rqerr").textContent="";return r.json();}
async function addReq(){const b={site:$("rqsite").value,url:$("rqurl").value,kind:$("rqkind").value,status:$("rqstatus").value,sent:$("rqsent").value,ref:$("rqref").value,note:$("rqnote").value};
 if(!b.site.trim()){$("rqerr").textContent="Indique le site ou l'organisme.";return;}
 if(await reqCall("POST","/api/requests",b)){["rqsite","rqurl","rqsent","rqref","rqnote"].forEach(i=>$(i).value="");$("rqstatus").value="à envoyer";await loadReqs();}}
async function updReq(id,k,v){await reqCall("PUT","/api/requests/"+id,{[k]:v});await loadReqs();}
async function delReq(id){if(!confirm("Supprimer cette demande du suivi ?"))return;await reqCall("DELETE","/api/requests/"+id);await loadReqs();}
async function checkReq(id){const r=await reqCall("POST",`/api/requests/${id}/check`);if(r)await loadReqs();}
function relance(id){const r=RQ.find(x=>x.id===id);if(!r)return;const nm=(($("idfirst").value+" "+$("idlast").value).trim())||"[Prénom Nom]";
 const what=r.kind==="source"?"d'effacement (article 17 du RGPD) de mes données personnelles":"de déréférencement de mes données personnelles";
 const delai=r.due?(r.overdue?`est dépassé depuis le ${frd(r.due)}`:`arrive à échéance le ${frd(r.due)}`):"est d'un mois à compter de la réception";
 $("dtitle").textContent="Relance — "+r.site;
 $("dtext").value=`Objet : Relance — ma demande ${what.startsWith("d'effacement")?"d'effacement":"de déréférencement"}${r.sent?" du "+frd(r.sent):""}${r.ref?" (réf. "+r.ref+")":""}

Madame, Monsieur,

${r.sent?"Le "+frd(r.sent)+", je":"Je"} vous ai adressé une demande ${what}${r.url?", concernant la page suivante : "+r.url:""}.${r.ref?" Référence de mon dossier : "+r.ref+".":""}

À ce jour, je n'ai reçu aucune réponse. Le délai d'un mois prévu à l'article 12.3 du RGPD ${delai} (il ne peut être prolongé de deux mois que pour une demande complexe, et à condition de m'en informer).

Je vous demande de me confirmer par écrit la suite donnée à ma demande sous huit jours. À défaut, je saisirai la CNIL.

Cordialement,
${nm}
[Date]

À relire avant envoi, à adresser toi-même au DPO / contact « vie privée » du site.`;dlg.showModal();}
function newReq(i){const it=AN&&AN.items[i];if(!it)return;setRq(true);$("rqsite").value=it.site;$("rqurl").value=/^https?:\/\//.test(it.url)?it.url:"";
 $("rqkind").value="source";$("rq").scrollIntoView({behavior:"smooth",block:"start"});$("rqsent").focus();}
$("rqadd").onclick=addReq;
// ---- comparaison entre analyses
async function loadCompare(){const id=cur;$("cmp").innerHTML="";if(!id)return;let d;try{d=await (await fetch(`/api/jobs/${id}/compare`)).json();}catch(e){return;}
 if(id!==cur)return;
 if(!d.previous){$("cmp").innerHTML=`<h3>Comparaison</h3><p class="mut" style="font-size:13px">Pas d'analyse précédente terminée avec les mêmes cibles. Relance-en une plus tard : l'app montrera ce qui est apparu ou disparu.</p>`;return;}
 const list=a=>a.length?`<ul style="margin:4px 0 0 18px;font-size:13px">${a.map(x=>`<li>${esc(x.site)} <span class="mut">(${esc(x.target)})</span> ${/^https?:\/\//.test(x.url)?`<a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">lien</a>`:""}</li>`).join("")}</ul>`:"";
 $("cmp").innerHTML=`<h3>Comparaison avec l'analyse du ${new Date(d.previous.created*1000).toLocaleString("fr-FR")}</h3>
  <div><span class="badge${d.new.length?" hot":""}">${d.new.length} nouveau(x)</span><span class="badge">${d.gone.length} disparu(s)</span><span class="badge">${d.same} inchangé(s)</span></div>
  ${d.new.length?`<details open><summary>Nouveaux comptes</summary>${list(d.new)}</details>`:""}
  ${d.gone.length?`<details><summary>Comptes non retrouvés cette fois</summary>${list(d.gone)}</details>`:""}
  ${d.caveats.length?`<p class="mut" style="font-size:12.5px">⚠ « Disparu » veut seulement dire « non détecté cette fois ». ${esc(d.caveats.join(" · "))}.</p>`:`<p class="mut" style="font-size:12.5px">« Disparu » peut aussi venir d'un site qui a bloqué le scan : vérifie à la main avant de conclure à une suppression.</p>`}`;}
// ---- recherche par nom
function renderNm(){const f=$("idfirst").value.trim(),l=$("idlast").value.trim(),city=$("nmcity").value.trim(),jb=$("nmjob").value.trim();
 try{localStorage.setItem("nm_extra",JSON.stringify([city,jb]));}catch(e){}
 if(!f&&!l){$("nmlinks").innerHTML=`<p class="mut">Renseigne ton prénom et ton nom dans « Qui suis-je ? » pour générer les liens.</p>`;return;}
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
  `<h3>Aide</h3><p style="font-size:13px"><a href="https://www.cnil.fr/fr/comprendre-mes-droits/le-droit-leffacement-supprimer-vos-donnees-en-ligne" target="_blank" rel="noopener noreferrer">CNIL : le droit à l'effacement</a> <span class="mut">(adresse tirée de ton guide, non vérifiée par moi)</span>. Pour chaque page à supprimer, ajoute-la dans « Suivi des demandes ».</p>`;}
try{const e=JSON.parse(localStorage.getItem("nm_extra")||"null");if(e){$("nmcity").value=e[0]||"";$("nmjob").value=e[1]||"";}}catch(e){}
["idfirst","idlast","nmcity","nmjob"].forEach(i=>$(i).addEventListener("input",renderNm));renderNm();loadReqs();
function pwShow(on){$("pwin").type=on?"text":"password";$("pweye").textContent=on?"🙈":"👁";$("pweye").setAttribute("aria-pressed",on?"true":"false");$("pweye").setAttribute("aria-label",on?"Masquer le mot de passe":"Afficher le mot de passe");}
$("pweye").onclick=()=>{pwShow($("pwin").type==="password");$("pwin").focus();};
$("pwgo").onclick=pwCheck;$("pwin").addEventListener("keydown",e=>{if(e.key==="Enter")pwCheck();});
function setPw(open){$("pwbody").style.display=open?"block":"none";$("pwtog").textContent=open?"▾ réduire":"▸ afficher";try{localStorage.setItem("pwopen",open?"1":"0");}catch(e){}}
$("pwhead").onclick=()=>setPw($("pwbody").style.display==="none");
try{if(localStorage.getItem("pwopen")==="0")setPw(false);}catch(e){}
function setCk(open){$("ckbody").style.display=open?"block":"none";$("cktog").textContent=open?"▾ réduire":"▸ afficher";try{localStorage.setItem("ckopen",open?"1":"0");}catch(e){}}
$("ckhead").onclick=()=>setCk($("ckbody").style.display==="none");
try{if(localStorage.getItem("ckopen")==="0")setCk(false);}catch(e){}
async function loadChecks(){try{ckDone=(await (await fetch("/api/checklist")).json()).done||{};}catch(e){}renderChecks();}
function renderChecks(){let n=0,t=0;
 $("cklist").innerHTML=CK.map(g=>`<h3>${esc(g.g)}</h3>`+g.i.map(([id,txt,url])=>{t++;const d=!!ckDone[id];if(d)n++;
  return `<label class="${d?"dn":""}"><input type="checkbox" ${d?"checked":""} onchange="toggleCheck('${id}',this.checked)"><span>${esc(txt)}${url?` <a href="${esc(url)}" target="_blank" rel="noopener noreferrer">↗ ouvrir</a>`:""}</span></label>`;}).join("")).join("");
 $("ckbar").style.width=(t?Math.round(100*n/t):0)+"%";$("cktxt").textContent=`${n}/${t} faits`;}
async function toggleCheck(id,v){ckDone[id]=v;renderChecks();
 try{await fetch("/api/checklist",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({id,done:v})});}catch(e){}}
try{const s=JSON.parse(localStorage.getItem("osint_id")||"null");if(s){$("idfirst").value=s[0]||"";$("idlast").value=s[1]||"";}}catch(e){}
addField("pseudos","pseudo");addField("emails","email@exemple.fr");loadHist();loadChecks();
</script></body></html>
"""

# ------------------------------------------------ Relance hebdomadaire (sans interface)
REPORT_DIR = BASE / "rapports_hebdo"


def rescan_cli():
    """Relance la dernière analyse terminée, la compare à la précédente et écrit un rapport.
    Ne contacte personne : aucune demande n'est envoyée, les relances restent à ta main."""
    load_jobs()
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
    os.chmod(REPORT_DIR, 0o700)
    out = REPORT_DIR / f"{today.isoformat()}.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Rapport :", out)
    msg = f"{len(cmp_['new'])} nouveau(x), {len(cmp_['gone'])} disparu(s), {len(late)} demande(s) en retard"
    print(msg)
    if shutil.which("notify-send"):
        subprocess.run(["notify-send", "Audit données perso", msg], check=False)
    return 0


def install_timer():
    d = Path.home() / ".config" / "systemd" / "user"
    d.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve()
    (d / "osint-rescan.service").write_text(
        "[Unit]\nDescription=Audit hebdomadaire de mes données perso (osint_app)\n\n"
        f"[Service]\nType=oneshot\nExecStart={quote_cmd(self_cmd() + ['--rescan'])}\n", encoding="utf-8")
    (d / "osint-rescan.timer").write_text(
        "[Unit]\nDescription=Audit hebdomadaire (lundi 09:00)\n\n"
        "[Timer]\nOnCalendar=Mon *-*-* 09:00:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n", encoding="utf-8")
    print("Fichiers écrits dans", d)
    print("Pour activer (rien n'est activé tant que tu ne le fais pas) :")
    print("  systemctl --user daemon-reload && systemctl --user enable --now osint-rescan.timer")
    print("Pour vérifier : systemctl --user list-timers | grep osint")
    print("Pour arrêter  : systemctl --user disable --now osint-rescan.timer")
    return 0


# ------------------------------------------------------- Fenêtre native (mode « application »)
HOST, PORT = "127.0.0.1", 8300
URL = f"http://{HOST}:{PORT}/"
BROWSERS = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "microsoft-edge"]
APP_ICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#1b2230"/>
<path d="M32 8l18 6v14c0 12-8 21-18 26C22 49 14 40 14 28V14z" fill="#6d8bff"/>
<circle cx="29" cy="29" r="8" fill="none" stroke="#fff" stroke-width="3"/><path d="M35 35l9 9" stroke="#fff" stroke-width="4" stroke-linecap="round"/></svg>
"""


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
    for b in BROWSERS:
        exe = shutil.which(b)
        if exe:
            cmd = [exe, f"--app={URL}", f"--user-data-dir={prof}", "--no-first-run", "--no-default-browser-check",
                   "--window-size=1280,900", "--class=osint-audit"]
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
        if shutil.which("xdg-open"):
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


def install_launcher():
    script = Path(__file__).resolve()
    apps = Path.home() / ".local" / "share" / "applications"
    icons = Path.home() / ".local" / "share" / "icons"
    apps.mkdir(parents=True, exist_ok=True)
    icons.mkdir(parents=True, exist_ok=True)
    (icons / "osint-audit.svg").write_text(APP_ICON, encoding="utf-8")
    desk = apps / "osint-audit.desktop"
    desk.write_text(
        "[Desktop Entry]\nType=Application\nName=Audit données perso\n"
        "Comment=Audit de mes propres données diffusées\n"
        f"Exec={quote_cmd(self_cmd() + ['--window'])}\n"
        f"Icon={icons / 'osint-audit.svg'}\nTerminal=false\nCategories=Utility;Security;\nStartupWMClass=osint-audit\n",
        encoding="utf-8")
    os.chmod(desk, 0o755)
    print("Lanceur écrit :", desk)
    print("Cherche « Audit données perso » dans le menu des applications (déconnexion/reconnexion si absent).")
    print("Pour l'épingler : clic droit sur l'icône > Ajouter aux favoris.")
    print("Pour le retirer : supprime ce fichier .desktop.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Audit de mes propres données diffusées")
    ap.add_argument("--rescan", action="store_true", help="relance la dernière analyse, compare et écrit un rapport (sans interface)")
    ap.add_argument("--window", action="store_true", help="ouvre l'application dans sa propre fenêtre (sans onglet de navigateur)")
    ap.add_argument("--install-launcher", action="store_true", help="crée l'icône dans le menu des applications")
    ap.add_argument("--install-timer", action="store_true", help="écrit un minuteur systemd hebdomadaire (utilisateur), sans l'activer")
    args = ap.parse_args()
    if args.install_launcher:
        sys.exit(install_launcher())
    if args.window:
        sys.exit(window_mode())
    if args.install_timer:
        sys.exit(install_timer())
    if args.rescan:
        sys.exit(rescan_cli())
    load_jobs()
    print("Interface : http://127.0.0.1:8300")
    uvicorn.run(app, host="127.0.0.1", port=8300, log_level="warning")


if __name__ == "__main__":
    main()
