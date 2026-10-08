# PyAntiSpam avec Docker

Déploiement recommandé : une stack Docker Compose. PyAntiSpam y tourne en mode daemon, avec rspamd en mode fantôme.

## Services

| Service | Image | Rôle |
|---|---|---|
| `pyantispam` | construite depuis le `Dockerfile` | Le daemon : `python -m pyantispam.cli daemon`, un cycle toutes les 300 s |
| `rspamd` | `rspamd/rspamd:4.2.1` | Second avis en mode fantôme, apprend de vos reclassements (`rspamd.enabled`) |
| `redis` | `redis:8.4-alpine` | Stockage rspamd (Bayes, cache) |
| `unbound` | `klutchell/unbound` | Résolveur DNS récursif pour rspamd. Les listes DNS publiques refusent souvent les requêtes qui passent par de gros résolveurs ouverts. |

Ils partagent tous le réseau `pyantispam-network`. Le contrôleur rspamd est publié sur le port `11334`.

Limites de ressources de `pyantispam` : 2 Go de mémoire et 2 CPU. CamemBERT occupe à lui seul environ 1,4 Go en pointe.

## Fichiers montés

| Hôte | Conteneur | |
|---|---|---|
| `./config.yaml` | `/app/config.yaml` | lecture seule |
| `./.env` | `/app/.env` | lecture seule, chargé aussi comme `env_file` |
| `./data/` | `/app/data` | tout l'état : modèles, exemples, listes, cache, journaux, cache CamemBERT (`hf_cache/`) |
| `./docker/rspamd/local.d/` | `/etc/rspamd/local.d` | configuration rspamd, lecture seule |
| `./docker/unbound/custom.conf.d/` | `/etc/unbound/custom.conf.d` | configuration unbound, lecture seule |

Le code est **copié dans l'image**, il n'est pas monté. Tout changement de code demande donc une reconstruction.

## Mise en place

```bash
cp config.yaml.example config.yaml
cp .env.example .env                       # mots de passe IMAP, clé LLM, RSPAMD_PASSWORD
cp docker/rspamd/local.d/worker-controller.inc.example docker/rspamd/local.d/worker-controller.inc
mkdir -p data
docker compose up -d --build

# mot de passe du contrôleur rspamd (le même que RSPAMD_PASSWORD dans .env) :
docker compose exec rspamd rspamadm pw    # coller le hash dans worker-controller.inc
docker compose restart rspamd
```

`worker-controller.inc` contient un secret : il est ignoré par git, seul l'exemple est versionné.

## Exploitation

```bash
docker compose ps                                     # état (pyantispam et rspamd ont un healthcheck)
docker compose logs -f --tail=100 pyantispam
tail -F data/logs/spam_decisions.log                  # décisions en direct, depuis l'hôte
docker compose exec pyantispam pyantispam stats       # une commande dans le conteneur
```

### Déployer un changement de code

```bash
git pull
docker compose build pyantispam
docker compose up -d pyantispam
```

Seul `pyantispam` redémarre. rspamd, redis et unbound ne sont pas touchés.

### Changer `config.yaml`

`config.yaml` est monté seul. Un éditeur qui remplace le fichier, comme `sed -i`, n'est pas vu par le conteneur en marche. Il faut recréer le conteneur :

```bash
docker compose up -d --force-recreate pyantispam
docker exec pyantispam grep -n "la_clé" /app/config.yaml     # vérifier la valeur lue
```

## Utilisateur du conteneur

Le compose lance `pyantispam` sous `user: "${UID}:${GID}"`. Si ces variables ne sont pas définies au moment de `docker compose`, le conteneur tourne en **root**, et les fichiers qu'il crée dans `data/` (dont `data/logs/`) appartiennent à root. Docker affiche alors l'avertissement `The "UID" variable is not set`.

Pour tourner sous votre utilisateur, ajoutez dans `.env` (le compose y lit ses variables) :

```bash
UID=1000      # résultat de: id -u
GID=1000      # résultat de: id -g
```

Puis remettez `data/` à votre nom (`sudo chown -R $(id -u):$(id -g) data`) avant de recréer le conteneur.

## Sauvegarde

`training_data.json` contient tous vos reclassements : c'est la donnée à ne pas perdre. `scripts/backup_training.sh` en garde une copie validée par jour dans `data/backups/`, avec 7 jours de rotation. Exemple de ligne cron sur l'hôte :

```
30 3 * * * cd /chemin/vers/PyAntiSpam && ./scripts/backup_training.sh >> data/backups/backup_training.log 2>&1
```

Le journal va dans `data/backups/` et non dans `data/logs/`. Si le conteneur tourne en root, `data/logs/` lui appartient, et cron ne peut pas y écrire.

Les copies restent sur la même machine. Pour une vraie sauvegarde, copiez aussi `data/` ailleurs.

## Fuseau horaire

`TZ=Europe/Paris` est défini dans l'image et dans le compose. Changez `TZ` pour un autre fuseau.

## Dépannage

- **Le conteneur redémarre en boucle** : vérifier `config.yaml` (`docker compose exec pyantispam pyantispam test-config`) et les variables de `.env`.
- **Délais IMAP** (`The read operation timed out`) : souvent passagers, le cycle suivant reprend. S'ils sont fréquents, augmentez `email_connection.timeout`.
- **rspamd désactivé au démarrage** : `RSPAMD_PASSWORD` manque dans `.env`.
- **Mémoire** : le premier score CamemBERT charge le modèle (environ 750 Mo, puis 1,4 Go en pointe). Avec `embeddings.enabled: false`, le daemon reste léger.
