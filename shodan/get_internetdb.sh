#!/usr/bin/env bash
# get_internetdb.sh — télécharge le dump SQLite « internetdb » de Shodan (Bulk Data, offre Enterprise)
#
# Usage :
#   SHODAN_API_KEY=xxxxxxxx ./get_internetdb.sh [destination]      (défaut : ./internetdb.sqlite)
#   FORCE=1 ./get_internetdb.sh                                     (ignore le contrôle d'ancienneté)
#
# Procédure suivie (documentation Shodan « Bulk Data / InternetDB ») :
#   shodan data download internetdb internetdb.sqlite.bz2  ->  renommage  ->  bunzip2
# Le fichier est remplacé de façon atomique ; l'ancienne version est conservée en .prev.
#
# Cron hebdomadaire (la base InternetDB est rafraîchie chaque semaine) :
#   0 6 * * 1  SHODAN_API_KEY=xxxx /chemin/get_internetdb.sh /data/internetdb.sqlite >> /var/log/internetdb.log 2>&1

set -euo pipefail

DEST="${1:-./internetdb.sqlite}"
# Chemin absolu AVANT tout 'cd' (sinon un chemin relatif pointerait dans le répertoire temporaire)
mkdir -p "$(dirname "$DEST")"
DEST="$(cd "$(dirname "$DEST")" && pwd)/$(basename "$DEST")"
MAX_AGE_DAYS="${MAX_AGE_DAYS:-6}"
FORCE="${FORCE:-0}"

say() { printf '[internetdb] %s\n' "$*"; }
die() { printf '[internetdb] ERREUR : %s\n' "$*" >&2; exit 1; }

# 0. Fraîcheur : inutile de retélécharger plusieurs Go si le fichier est récent
if [[ -f "$DEST" && "$FORCE" != "1" ]]; then
  if [[ -z "$(find "$DEST" -mtime +"$MAX_AGE_DAYS" -print 2>/dev/null)" ]]; then
    say "$DEST a moins de $MAX_AGE_DAYS jours : rien à faire (FORCE=1 pour forcer)."
    exit 0
  fi
fi

# 1. Prérequis
command -v bunzip2 >/dev/null || die "bunzip2 introuvable (paquet bzip2)."
if ! command -v shodan >/dev/null; then
  command -v pip >/dev/null || command -v pip3 >/dev/null || die "ni 'shodan' ni pip disponibles."
  say "Installation du CLI Shodan (pip install --user shodan)…"
  (pip install --user shodan 2>/dev/null || pip3 install --user shodan)
  export PATH="$HOME/.local/bin:$PATH"
  command -v shodan >/dev/null || die "CLI 'shodan' installé mais absent du PATH (~/.local/bin)."
fi

# 2. Clé API (sans clé fournie, on suppose un 'shodan init' déjà fait)
if [[ -n "${SHODAN_API_KEY:-}" ]]; then
  shodan init "$SHODAN_API_KEY" >/dev/null
else
  say "SHODAN_API_KEY absente : utilisation de la configuration 'shodan init' existante."
fi

# 3. Téléchargement dans un répertoire temporaire, sur le même volume que la destination
DEST_DIR="$(dirname "$DEST")"
WORK="$(mktemp -d "$DEST_DIR/.internetdb.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
say "Espace disque libre dans $DEST_DIR : $(df -h "$DEST_DIR" | awk 'NR==2{print $4}') (prévoir plusieurs fois la taille de l'archive)."

cd "$WORK"
say "Téléchargement (peut être long) : shodan data download internetdb internetdb.sqlite.bz2"
if ! shodan data download internetdb internetdb.sqlite.bz2; then
  die "échec. Le dump InternetDB exige un compte Enterprise : vérifiez 'shodan data list --dataset=internetdb'."
fi

# La CLI préfixe le nom du fichier par celui du dataset (internetdb-internetdb.sqlite.bz2)
ARCHIVE="$(ls -1 *internetdb.sqlite.bz2 2>/dev/null | head -n1 || true)"
[[ -n "$ARCHIVE" ]] || die "archive .bz2 introuvable après téléchargement."
mv "$ARCHIVE" internetdb.sqlite.bz2

say "Décompression…"
bunzip2 -f internetdb.sqlite.bz2
[[ -s internetdb.sqlite ]] || die "fichier décompressé vide."

# 4. Contrôle léger : le fichier s'ouvre en lecture seule et contient au moins une table
if command -v sqlite3 >/dev/null; then
  TABLES="$(sqlite3 "file:$WORK/internetdb.sqlite?mode=ro" ".tables")" || die "SQLite ne parvient pas à ouvrir le fichier."
  say "Tables : $TABLES"
  say "Schéma :"; sqlite3 "file:$WORK/internetdb.sqlite?mode=ro" ".schema" | sed 's/^/    /'
else
  python3 - "$WORK/internetdb.sqlite" <<'PY' || die "SQLite ne parvient pas à ouvrir le fichier."
import sqlite3, sys
c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
for n, s in c.execute("SELECT name, sql FROM sqlite_master WHERE type IN ('table','index')"):
    print(f"[internetdb]     {s}")
PY
fi

# 5. Mise en place atomique (même volume => mv est un simple renommage)
[[ -f "$DEST" ]] && mv -f "$DEST" "$DEST.prev"
mv -f "$WORK/internetdb.sqlite" "$DEST"
say "OK : $DEST ($(du -h "$DEST" | cut -f1))"
say "Vérifiez que le schéma ci-dessus correspond à celui attendu par echo_2026_v5-shadow.py (table 'internetdb', colonne 'ip')."
