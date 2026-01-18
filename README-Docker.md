dis# 🐳 PyAntiSpam – Guide Docker complet

Ce document explique comment construire, configurer et exécuter PyAntiSpam avec Docker et Docker Compose.

PyAntiSpam fonctionne en mode « daemon » dans le conteneur et lit sa configuration depuis `config.yaml` et des secrets via un fichier `.env`.

---

## ✅ Prérequis
- Docker 20+ installé et en fonctionnement
- Optionnel mais recommandé: Docker Compose v2+
- Accès Internet pour télécharger les images et dépendances

---

## 🧰 Contenu Docker dans ce dépôt
- `Dockerfile` : image basée sur python:3.11-slim, exécution en utilisateur non-root, healthcheck, CMD daemon
- `docker-compose.yml` : service unique `pyantispam` avec volumes, env_file, logs, limites de ressources
- `scripts/docker-run.sh` : script helper pour construire/démarrer/stopper/consulter les logs sans Compose

### ⏰ Fuseau horaire
- Le fuseau horaire du conteneur est configuré par défaut sur `Europe/Paris` (installation de `tzdata` + variables d'environnement).
- Avec Docker Compose, c'est défini via `environment: TZ=Europe/Paris` (déjà présent dans `docker-compose.yml`).
- Avec `docker run`, le script ajoute automatiquement `-e TZ=Europe/Paris`.
- Pour utiliser un autre fuseau, remplacez la valeur de `TZ` (ex: `TZ=UTC` ou `TZ=America/New_York`).

---

## 🗂️ Répertoires et fichiers persistants
Les chemins côté hôte sont montés dans le conteneur pour conserver l'état:
- `./config.yaml` → `/app/config.yaml` (lecture seule)
- `./.env` → `/app/.env` (lecture seule)
- `./data/` → `/app/data` (listes, modèles ML, cache LLM, logs rotatifs…)

Créez ces éléments si besoin:

```
mkdir -p data
cp config.yaml.example config.yaml   # si vous partez de zéro
cp .env.example .env                 # si disponible, sinon créez .env
```

**Note** : Les logs sont maintenant stockés dans `data/logs/` avec rotation automatique. Le dossier est créé automatiquement au premier lancement.

---

## 🔐 Configuration des secrets (.env)
Le fichier `.env` n’est pas versionné. Il contient les clés API et mots de passe.
Exemples (adaptez selon votre `config.yaml`):

```
# LLM
OPENAI_API_KEY=sk-...            # si llm.provider=openai
ANTHROPIC_API_KEY=...            # si llm.provider=anthropic

# Mots de passe IMAP (doivent correspondre aux champs password_env de config.yaml)
EMAIL_PASSWORD_PERSONAL=...
EMAIL_PASSWORD_PRO=...
EMAIL_PASSWORD_OTHER=...
```

Dans `config.yaml`, la clé `llm.api_key_env` indique quelle variable d’environnement sera lue dans le conteneur (ex: `OPENAI_API_KEY`). Les comptes e‑mail doivent définir `password_env` et la variable correspondante doit exister dans `.env`.

---

## ⚙️ Configuration de l’application (config.yaml)
- Copiez `config.yaml.example` vers `config.yaml`
- Ajustez:
  - `llm.provider` et `llm.model`
  - `llm.cache.file_path`: par défaut `data/llm_cache.json` (persistant via le volume)
  - `email_accounts`: serveurs IMAP, utilisateurs et `password_env`
  - `actions` et `detection` selon votre politique

Astuce: laissez `data/` et `logs/` montés pour conserver l’historique et les caches.

---

## 🚀 Démarrage rapide (recommandé: Docker Compose)
1) Construire et démarrer en arrière-plan:

```
docker compose up -d --build
```

2) Suivre les logs:
```
docker compose logs -f --tail=100
```

3) Arrêter:
```
docker compose stop
```

4) Mettre à jour (reconstruire):
```
docker compose build --no-cache && docker compose up -d
```

Note: selon votre installation, la commande peut être `docker-compose` au lieu de `docker compose`.

---

## 🔁 Alternative: script helper
Le script `scripts/docker-run.sh` gère la construction et l’exécution même sans Compose.

Commandes principales:
- `./scripts/docker-run.sh build`  → construit l’image locale `pyantispam:latest`
- `./scripts/docker-run.sh start`  → construit si besoin et lance le conteneur
- `./scripts/docker-run.sh logs`   → suit les logs
- `./scripts/docker-run.sh stop`   → arrête le conteneur
- `./scripts/docker-run.sh shell`  → ouvre un shell dans le conteneur
- `./scripts/docker-run.sh stats`  → affiche les statistiques de PyAntiSpam

---

## 🧪 Vérifier que tout fonctionne
- Le conteneur expose un healthcheck interne; vous pouvez vérifier l'état avec:

```
docker ps
```

- Les logs sont stockés dans `./data/logs/` avec rotation automatique :
  - `data/logs/spam_decisions.log` : Décisions spam/ham uniquement (audit)
  - `data/logs/pyantispam.log` : Tous les événements système (debug complet)
- Le cache LLM persistant est dans `./data/llm_cache.json` si activé dans `config.yaml`.

**Consulter les logs** :
```bash
# Suivre les décisions en temps réel
tail -F data/logs/spam_decisions.log

# Suivre les logs système
tail -F data/logs/pyantispam.log

# Depuis le conteneur
docker compose exec pyantispam tail -f /app/data/logs/spam_decisions.log
```

---

## 🧱 Réseau et ports
- Un réseau `pyantispam-network` (bridge) est créé via docker-compose.
- Le Dockerfile expose le port 8000 pour de futures API web, mais aucune interface web n’est publiée par défaut. Si vous ajoutez une API, mappez le port:

```
# Exemple (à adapter dans docker-compose.yml)
ports:
  - "8000:8000"
```

---

## 📦 Sauvegardes et persistance
Sauvegardez régulièrement `data/` (qui inclut désormais les logs). Exemple de backup simple:

```
tar czf backup-$(date +%F).tar.gz data config.yaml
```

**Note** : Les logs sont dans `data/logs/` avec rotation automatique (pas besoin de dossier `logs/` séparé).

---

## 🔒 Sécurité et bonnes pratiques
- L’image s’exécute en utilisateur non‑root pour limiter l’impact d’un incident.
- Montez `config.yaml` et `.env` en lecture seule comme déjà prévu.
- Restreignez les droits sur `.env` (chiffrement/permissions strictes).
- Si vous utilisez des fournisseurs LLM, surveillez vos quotas et la confidentialité.

---

## 🛠️ Dépannage
- Le conteneur s’arrête immédiatement:
  - Vérifiez la validité de `config.yaml` et la présence des variables `.env` requises.
  - Consulter `docker compose logs` pour l’erreur détaillée.
- Erreurs d'IMAP (SSL, déconnexion, timeout):
  - Ajustez `email_connection.request_delay` dans `config.yaml` (ex: 0.1 s) pour réduire la charge.
  - Augmentez `email_connection.timeout` (ex: 30 s) pour les serveurs lents.
  - Vérifiez les ports/SSL de vos serveurs IMAP.
- LLM indisponible / temps de réponse long:
  - Activez le cache (`llm.cache.enabled: true`) et assurez un volume persistant sur `data/`.
- Problèmes de permissions sur volumes:
  - Assurez-vous que votre utilisateur hôte possède les dossiers `data/` et `logs/`.

---

## ❓ FAQ
- Où placer `config.yaml` ?
  - À la racine du projet, monté en `/app/config.yaml` dans le conteneur via Compose.
- Puis-je utiliser un autre provider LLM ?
  - Oui, mettez `llm.provider` à `anthropic` ou `ollama` et ajustez `api_key_env` et/ou la configuration du provider.
- Comment lancer temporairement en mode interactif ?
  - `docker compose run --rm pyantispam bash` puis exécutez des commandes Python.

---

## 📄 Licence
Ce guide accompagne PyAntiSpam. Reportez‑vous au fichier LICENSE du projet pour les conditions.
