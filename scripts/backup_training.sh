#!/usr/bin/env bash
# Copie quotidienne de data/training_data.json, validée et avec rotation.
# Lecture seule sur la source : le daemon n'est pas touché.
# Usage : scripts/backup_training.sh [dossier_data] [jours_a_garder]
set -euo pipefail

DATA_DIR="${1:-data}"
KEEP_DAYS="${2:-7}"
SRC="$DATA_DIR/training_data.json"
DEST_DIR="$DATA_DIR/backups"
STAMP="$(date +%Y%m%d)"
DEST="$DEST_DIR/training_data-$STAMP.json"

mkdir -p "$DEST_DIR"
TMP="$(mktemp "$DEST_DIR/.tmp.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

cp -- "$SRC" "$TMP"

# Ne garder la copie que si elle est lisible et contient une liste.
python3 - "$TMP" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(data, list):
    raise SystemExit("sauvegarde invalide : pas une liste")
print(f"{len(data)} entrées, {sum(1 for s in data if s.get('is_spam'))} spams")
PY

mv -f -- "$TMP" "$DEST"
trap - EXIT
chmod 0644 "$DEST"

# Rotation : supprimer les sauvegardes plus vieilles que KEEP_DAYS jours.
find "$DEST_DIR" -maxdepth 1 -name 'training_data-*.json' -mtime +"$KEEP_DAYS" -delete

echo "sauvegarde : $DEST"
