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

# Bayes de rspamd (volume Docker redis-data) : il ne se reconstruit pas, les
# mails bruts n'étant pas gardés. Au mieux : un échec ici (redis arrêté, pas de
# Docker) n'annule pas la sauvegarde de training_data.json ci-dessus.
backup_bayes() {
    local before rdb="$DEST_DIR/rspamd-redis-$STAMP.rdb"
    before="$(docker compose exec -T redis redis-cli LASTSAVE)" || return 1
    docker compose exec -T redis redis-cli BGSAVE >/dev/null || return 1
    for _ in $(seq 60); do
        [ "$(docker compose exec -T redis redis-cli LASTSAVE)" != "$before" ] && break
        sleep 1
    done
    docker compose cp redis:/data/dump.rdb "$rdb.tmp" || return 1
    mv -f -- "$rdb.tmp" "$rdb"
    chmod 0644 "$rdb"
    find "$DEST_DIR" -maxdepth 1 -name 'rspamd-redis-*.rdb' -mtime +"$KEEP_DAYS" -delete
    echo "sauvegarde Bayes rspamd : $rdb ($(stat -c %s "$rdb") octets)"
}
backup_bayes || echo "sauvegarde Bayes rspamd impossible (redis arrêté ?) ; training_data est sauvegardé" >&2
