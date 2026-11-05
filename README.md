# osint-audit — auditer ses propres données diffusées

Application **locale** (une interface web servie sur ton PC, ouvrable dans une fenêtre autonome) pour voir **ce qui circule sur toi sur Internet** : comptes liés à tes pseudos, sites liés à tes adresses email, fuites de données connues, et suivi des demandes de suppression (RGPD).

> **Usage strictement personnel.** À utiliser uniquement sur **tes propres** pseudos, adresses email et nom. Ne l'utilise jamais pour chercher des informations sur une autre personne.

Statut : projet personnel en cours, dépôt privé. Aucune licence n'est définie pour l'instant.

---

## Ce que fait l'application

| Domaine | Fonction |
|---|---|
| **Scan** | Plusieurs pseudos et emails à la fois. Pseudos : [Maigret](https://github.com/soxoj/maigret) (milliers de sites, infos de profil) et [Sherlock](https://github.com/sherlock-project/sherlock) (≈ 400 sites, variantes `{?}`). Emails : [Holehe](https://github.com/megadose/holehe) (sites où l'email a un compte). |
| **Suivi** | Progression par cible (estimée au temps écoulé), journal en direct, durée maximale par outil avec **conservation des résultats partiels**, annulation, une analyse à la fois (file d'attente). |
| **Analyse** | Catégorie et sensibilité de chaque compte, estimation « est-ce moi ? » (comparaison du nom affiché avec ton prénom/nom), données visibles publiquement, plan d'action, graphiques, assistant IA optionnel. |
| **Rapport** | Site par site, export CSV / JSON, modèles de demande RGPD (art. 15 accès, art. 17 effacement). |
| **Fuites** | Saisie manuelle des fuites trouvées (par ex. via le compte gratuit de haveibeenpwned.com), avec conseils déduits des données exposées. |
| **Mots de passe** | Test Pwned Passwords (k-anonymat : l'empreinte SHA-1 est calculée dans le navigateur, seuls 5 caractères sont envoyés). Bouton « œil » pour contrôler la saisie. |
| **Demandes** | Suivi des demandes de suppression : statut, date d'envoi, échéance à 1 mois (art. 12.3), relance préparée (jamais envoyée automatiquement), vérification que la page répond encore. |
| **Comparaison** | Compare une analyse à la précédente : nouveaux comptes, comptes non retrouvés, inchangés. |
| **Recherche par nom** | Liens de recherche pré-remplis (moteurs, annuaires, réseaux). Tu les ouvres toi-même. |
| **Checklist** | Contrôles à faire à la main, cases enregistrées localement. |
| **Relance hebdomadaire** | `--rescan` sans interface + minuteur systemd optionnel. |

## Installation (Linux, testé sur Zorin OS)

Prérequis : Python ≥ 3.10, `python3-venv`.

```bash
mkdir -p ~/osint && cd ~/osint
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn maigret holehe sherlock-project
cp /chemin/vers/osint_app.py ~/osint/
python osint_app.py            # puis ouvrir http://127.0.0.1:8300
```

Le serveur n'écoute que sur `127.0.0.1` (rapports = données personnelles agrégées).

### Fenêtre autonome et icône

```bash
python osint_app.py --window            # fenêtre d'application sans onglets
python osint_app.py --install-launcher  # icône « Audit données perso » dans le menu
```

La fenêtre utilise Chrome, Chromium, Brave ou Edge avec un profil séparé (`~/osint/.window-profile`). Sans eux, l'application s'ouvre dans le navigateur par défaut. Fermer la fenêtre arrête le serveur, sauf si une analyse est en cours (elle se termine d'abord).

### Relance hebdomadaire (facultatif)

```bash
python osint_app.py --rescan          # relance la dernière analyse, compare, écrit un rapport
python osint_app.py --install-timer   # écrit un minuteur systemd (lundi 9 h), sans l'activer
systemctl --user daemon-reload && systemctl --user enable --now osint-rescan.timer
```

Rapports dans `~/osint/rapports_hebdo/`. Aucune demande n'est envoyée automatiquement.

## AppImage (sans installer Python)

Un seul fichier exécutable qui embarque Python 3.12, Maigret, Sherlock, Holehe, FastAPI et uvicorn. Chrome/Chromium/Brave/Edge n'est **pas** embarqué : il doit être installé pour la fenêtre autonome.

```bash
chmod +x osint-audit-x86_64.AppImage
./osint-audit-x86_64.AppImage                     # fenêtre autonome (= --window)
./osint-audit-x86_64.AppImage --serve             # serveur seul, puis http://127.0.0.1:8300
./osint-audit-x86_64.AppImage --install-launcher  # icône du menu, pointe vers l'AppImage
./osint-audit-x86_64.AppImage --rescan
```

Sur Ubuntu 22.04+/Zorin, `libfuse2` est nécessaire (`sudo apt install libfuse2`), ou lancer avec `--appimage-extract-and-run`. Les données restent dans `~/osint/`. Si l'AppImage est déplacée, relancer `--install-launcher` (et `--install-timer` si utilisé).

### Construire

```bash
pip install python-appimage==1.4.7
scripts/build_appimage.sh     # -> osint-audit-x86_64.AppImage + .sha256
scripts/smoke_test.sh         # vérifications rapides sans réseau
```

La recette est dans `appimage/` (`.desktop`, `.appdata.xml`, icône, `requirements.txt`, `entrypoint.sh`). GitHub Actions (`.github/workflows/appimage.yml`) construit et teste à chaque pull request ; un tag `v*` publie l'AppImage dans une release :

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Configuration

| Réglage | Où | Défaut |
|---|---|---|
| Dossier de données | carte « Dossier de données » de l'interface (enregistré dans `~/.config/osint-audit/settings.json`), ou variable `OSINT_DATA_DIR`, ou option `--data-dir DOSSIER` | `~/osint` |
| Serveur Ollama de l'assistant | variable `OLLAMA_URL`, ou `~/osint/config.json` : `{"ollama_url": "http://hote:11434"}` | `http://127.0.0.1:11434` |

Dossier de données : `--data-dir`, puis `OSINT_DATA_DIR`, puis le réglage de l'interface, puis `~/osint`. Le changement s'applique au redémarrage ; l'option « copier mes données actuelles » copie sans rien supprimer. `--install-launcher` et `--install-timer` inscrivent `--data-dir` quand le dossier vient de l'option ou de la variable.

Ollama : variable d'environnement, puis `config.json`, puis la valeur par défaut. L'assistant est facultatif : sans Ollama, tout le reste fonctionne.

## Données stockées (dans le dossier de données, `~/osint/` par défaut, mode 700)

| Fichier / dossier | Contenu |
|---|---|
| `jobs/<id>/job.json` + sorties des outils | Analyses |
| `leaks.json` | Fuites notées à la main (bouton « Exporter » de la carte Fuites : télécharge ce fichier) |
| `demandes.json` | Suivi des demandes de suppression |
| `checklist.json` | Cases cochées |
| `rapports_hebdo/` | Rapports du mode `--rescan` |
| `config.json` | Réglages facultatifs |

Ces fichiers contiennent des données personnelles : **ne les versionne jamais**.

## Ce qui sort de ta machine

- Les **scans** envoient les pseudos et emails aux sites testés (c'est leur principe).
- **Pwned Passwords** : 5 caractères d'une empreinte, jamais le mot de passe.
- **Vérification de page** (suivi des demandes) : une requête vers le lien que tu as saisi.
- **Recherche par nom** : ton nom est transmis au moteur choisi quand tu cliques un lien.
- **Assistant** : uniquement vers l'Ollama configuré.
- Rien d'autre, pas de télémétrie.

## Limites connues (à lire)

- **Holehe** : sur une adresse testée, seuls 41 des 122 modules ont répondu de façon fiable. « 0 compte trouvé » ne signifie pas « aucun compte ». Un indicateur de couverture est affiché.
- **Maigret / Sherlock** : faux positifs possibles (homonymes, pages qui répondent toujours). Certains sites bloquent les scans (« Bot protection ») et sont absents du résultat.
- **Fuites** : l'application ne se connecte pas à l'API HIBP (payante). Les fuites sont saisies à la main. Les fuites jugées sensibles par HIBP ne renvoient jamais d'adresses.
- **Dark web** : non couvert.
- **« Disparu »** dans la comparaison veut dire « non détecté cette fois », pas forcément « supprimé ».
- La vérification d'une page ne détecte pas les pages vides sans code d'erreur : confirme à la main.
- Les conseils sur les fuites viennent de mots-clés, ils ne remplacent pas la lecture de la fiche de la fuite.
- Tests : faits avec de faux outils et un navigateur piloté (le réseau est bloqué dans l'environnement de développement). Maigret, Sherlock et Holehe ont tourné sur le poste de l'utilisateur ; les ajouts récents (suivi des demandes, comparaison, vérification de page, `--rescan`, minuteur, fenêtre autonome sur un vrai bureau) n'ont pas encore été vus en conditions réelles.

## Architecture

Un seul fichier, `osint_app.py` :

- **FastAPI + uvicorn**, une interface HTML/JS intégrée, aucune dépendance front externe.
- Un thread par analyse, un verrou global (une analyse à la fois), groupes de processus tués proprement (SIGTERM puis SIGKILL).
- Les outils sont lancés par `python -I -m maigret` / `-m sherlock_project` ; Holehe passe par un petit wrapper qui neutralise sa vérification de mise à jour au démarrage (`check_update`) et n'utilise jamais l'option `-T` (cassée en 1.61).
- Moteur d'analyse **déterministe** (sans IA) : catégories, sensibilité, correspondance, score de priorité.
- API principale : `/api/jobs` (création, état, annulation, suppression, export, analyse, comparaison), `/api/requests`, `/api/leaks`, `/api/checklist`, `/api/pwned/range/{prefix}`, `/api/assistant/*`.

## Pistes (non faites)

- Intégration de l'API HIBP (clé lue dans la variable `HIBP_API_KEY`, jamais saisie dans l'interface).
- Bouton « relancer seulement les sites bloqués ».
- Tests automatisés.
- Choix d'une licence.
