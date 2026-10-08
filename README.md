### Projet démarré en vibecoding et retouché à la main :)
# PyAntiSpam

Antispam IMAP auto-hébergé, indépendant de l'hébergeur de messagerie. Il surveille une ou plusieurs boîtes, déplace les spams dans un dossier dédié, et apprend uniquement des corrections que vous faites depuis votre client mail.

Il tourne en continu (mode daemon, conseillé via Docker, voir [README-Docker.md](README-Docker.md)) ou ponctuellement en ligne de commande.

## Principes

- **Ne jamais perdre un mail.** Dans le doute, le mail est gardé. Un spam est *déplacé*, jamais supprimé (sauf purge explicite, désactivée par défaut).
- **Apprendre seulement de l'utilisateur.** Les modèles n'apprennent que de vos reclassements (dossiers de feedback). Jamais de leurs propres décisions ni de celles du LLM.
- **Mesurer avant de faire confiance.** Les nouveaux classifieurs tournent d'abord en « mode fantôme » : ils notent leur avis à côté de la vraie décision, sans agir.

## Chaîne de décision

Chaque mail **non lu** de la boîte de réception passe dans cet ordre :

```
Mail non lu
    │
    ├─ 1. Liste blanche / noire ─────────── GARDER / SPAM   (sauf lists.shadow: true)
    ├─ 2. Correction déjà faite par vous ── votre décision  (mémoire des corrections)
    ├─ 3. Random Forest, si confiant ────── GARDER / SPAM   (confiance > ml_confidence_threshold)
    ├─ 4. LLM, pour les cas incertains ──── GARDER / SPAM   (verdict mis en cache)
    └─ 5. Par défaut ────────────────────── GARDER
```

- Un mail lu avant le passage du daemon n'est pas traité.
- Un mail gardé reste non lu.
- Une règle « marketing » écrite à la main peut s'ajouter au Random Forest (`classify_marketing_as_spam`). Elle est **désactivée par défaut** : à poids fixes et sans apprentissage, elle classait en spam des mails de fournisseurs.

## Apprentissage

### Dossiers de feedback

Ils sont créés automatiquement dans chaque compte. Déplacez-y un mail depuis votre client :

| Dossier | Effet | Le mail finit dans |
|---|---|---|
| `PYANTISPAM_IS_SPAM` | Spam manqué : appris comme spam | le dossier spam |
| `PYANTISPAM_NOT_SPAM` | Faux positif : appris comme légitime | la boîte de réception |
| `PYANTISPAM_BLACKLIST` | Ajoute l'expéditeur à la liste noire et l'apprend | le dossier spam |
| `PYANTISPAM_WHITELIST` | Ajoute l'expéditeur à la liste blanche et l'apprend | la boîte de réception |

Les dossiers sont traités à chaque cycle. Le mail est copié vers sa destination avant d'être retiré du dossier de feedback.

Chaque reclassement :
1. est ajouté à `data/training_data.json`, sans jamais écraser l'existant ;
2. est mémorisé (`data/llm_cache.json`) : un mail identique (même expéditeur, même sujet, même début de corps) recevra désormais votre décision ;
3. est appris par rspamd (`learnspam` / `learnham`), si rspamd est activé ;
4. fait avancer le compteur de réentraînement (`data/retrain_state.json`).

### Réentraînement

Quand `learning.retrain_threshold` reclassements (10 par défaut) sont atteints, le Random Forest est réentraîné **une fois en fin de cycle, sur tout l'historique**. Une rafale de corrections donne donc un seul réentraînement.

Pondération des exemples : 1 par défaut, 1,5 pour un expéditeur déjà corrigé 2 fois, 5 pour un expéditeur récurrent (3 corrections ou plus).

Si le modèle est absent ou si le jeu de paramètres change, il est réentraîné sur l'historique. Sans données, il reste indisponible, et les mails sont gardés.

### Listes automatiques

Après `auto_blacklist_threshold` reclassements « spam » (3 par défaut) pour un même expéditeur, il passe en liste noire. Même principe pour la liste blanche. Voir `pyantispam recurring-senders`.

## Le Random Forest

81 paramètres extraits de chaque mail :

- **Expéditeur (11)** : historique de vos corrections (ratio spam, nombre de feedbacks, récurrence), forme de l'adresse, TLD suspect
- **Sujet (15)** et **contenu (25)** : longueur, majuscules, ponctuation, mots-clés (urgence, argent, phishing, marketing), liens, liens de suivi, boutons d'action, prix
- **Texte (5)** : entropie, diversité lexicale, répétitions
- **HTML (5)** : ratio HTML/texte, images, formulaires, scripts, densité de liens
- **En-têtes (10)** : SPF, DKIM, DMARC, cohérence From/DKIM et Message-ID, Reply-To, nombre de relais, `List-Unsubscribe`, score `X-Spam-Status` de l'hébergeur
- **Horaire (5)** et **interactions (5)** entre signaux

## Modes fantôme

Ils notent un score pour chaque mail, à côté de la vraie décision, sans jamais agir.

| Classifieur | Activation | Journal |
|---|---|---|
| Random Forest (probabilité brute, même quand une liste ou le LLM décide) | toujours | `data/logs/ml_shadow_log.jsonl` |
| CamemBERT (`sentence-camembert-base` + régression logistique réapprise sur vos reclassements) | `embeddings.enabled` | `data/logs/embedding_shadow_log.jsonl` |
| rspamd (stack Docker fournie) | `rspamd.enabled` | `data/logs/rspamd_shadow_log.jsonl` |
| Listes blanche / noire | `lists.shadow` | champ `shadow_list` de `prediction_log.jsonl` |

Le journal `data/logs/prediction_log.jsonl` contient une ligne par décision réelle.

## Installation

```bash
git clone https://github.com/pierre0412/PyAntiSpam.git
cd PyAntiSpam
python -m venv venv
source venv/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cpu   # seulement pour CamemBERT
pip install -r requirements.txt
pip install -e .
```

## Configuration

```bash
cp config.yaml.example config.yaml   # réglages, commentés
cp .env.example .env                 # mots de passe et clés, jamais commités
pyantispam test-config               # vérifie la configuration et les connexions
```

Points clés de `config.yaml` (tout est commenté dans `config.yaml.example`) :

```yaml
llm:
  provider: "mistral"              # mistral, openai ou anthropic (clé dans .env)
  model: "mistral-medium-latest"

email_accounts:
  - name: "personal"
    server: "imap.example.com"
    port: 993
    username: "vous@example.com"
    password_env: "EMAIL_PASSWORD_PERSONAL"
    spam_folder: "Junk"            # optionnel, sinon actions.move_spam_to_folder

detection:
  ml_confidence_threshold: 0.8
  use_llm_for_uncertain: true
  classify_marketing_as_spam: false

lists:
  shadow: false                    # true : les listes sont seulement journalisées

learning:
  retrain_threshold: 10

actions:
  auto_delete_after_days: 0        # purge du dossier spam (0 = jamais, conseillé)
```

## Commandes

```bash
pyantispam daemon                    # boucle continue (défaut : toutes les 300 s, --interval)
pyantispam run                       # un passage : feedbacks puis nouveaux mails
pyantispam run --account personal    # un seul compte
pyantispam run --dry-run             # se connecte sans rien traiter (test de connexion)
pyantispam test-config
pyantispam setup                     # assistant de configuration

pyantispam whitelist add|remove|list [adresse ou domaine]
pyantispam blacklist add|remove|list [adresse ou domaine]

pyantispam status
pyantispam stats [--daily --days 7] [--export fichier.json]
pyantispam recurring-senders [--spam-only|--ham-only] [--threshold 2] [--limit 20]
```

## Évaluation

Ces scripts sont en lecture seule. Ils se lancent depuis le dossier qui contient `data/`, et ils ne touchent ni aux mails ni aux données.

| Script | Rôle |
|---|---|
| `live_eval.py` | Mesure sur le trafic réel : votre reclassement fait foi, sinon la décision est tenue pour juste. Compare PyAntiSpam, Random Forest, CamemBERT, leur moyenne et le LLM. `--depuis "AAAA-MM-JJ HH:MM"` donne une série par tranches. |
| `shadow_report.py` | Désaccords PyAntiSpam / CamemBERT, avec les verdicts relus à la main (`data/human_verdicts.json`). |
| `split_eval.py` | Validation croisée groupée par domaine expéditeur sur `training_data.json` : paramètres d'en-tête contre contenu contre CamemBERT. |

Limites de `live_eval.py` : les faux positifs sont bien mesurés, puisque vous les corrigez, mais les spams non vus dans la boîte de réception comptent comme justes.

## Fichiers de données (`data/`)

| Fichier | Contenu |
|---|---|
| `training_data.json` | Exemples étiquetés (vos reclassements) |
| `backups/` | Copie quotidienne de `training_data.json`, gardée 7 jours (`scripts/backup_training.sh`, via cron) |
| `spam_model.pkl`, `feature_scaler.pkl`, `feature_names.json` | Random Forest entraîné |
| `retrain_state.json` | Compteur de reclassements depuis le dernier réentraînement |
| `llm_cache.json` | Verdicts LLM et vos corrections, par empreinte de mail |
| `whitelist.json`, `blacklist.json` | Listes |
| `sender_feedback_history.json` | Corrections par expéditeur (listes automatiques) |
| `spam_stats.json`, `processed_emails.json` | Statistiques (`pyantispam stats`) |
| `human_verdicts.json` | Verdicts relus à la main, pour les rapports seulement |
| `hf_cache/` | Modèle CamemBERT téléchargé |
| `logs/` | Journaux, voir ci-dessous |

## Journaux

```bash
tail -F data/logs/spam_decisions.log    # décisions en direct
tail -F data/logs/pyantispam.log        # tout le système
grep ERROR data/logs/pyantispam.log
grep "\[account: personal\]" data/logs/spam_decisions.log
```

- `pyantispam.log` : tous les événements, rotation à 10 Mo, 5 fichiers gardés.
- `spam_decisions.log` : décisions uniquement, rotation à 20 Mo, 10 fichiers gardés.
- `*.jsonl` : journaux structurés pour l'évaluation (décisions et modes fantôme), avec un index `*_seen.json` qui évite les doublons.

## Architecture

```
src/pyantispam/
├── cli.py               commandes, boucle du daemon
├── config/              config.yaml + .env
├── email/               client IMAP, chaîne de décision (email_processor.py)
├── filters/             listes blanche / noire
├── ml/                  extraction des paramètres, Random Forest, stockage atomique des exemples
├── llm/                 Mistral / OpenAI / Anthropic
├── learning/            dossiers de feedback, réentraînement
├── embeddings/          CamemBERT en mode fantôme
├── rspamd/              rspamd en mode fantôme
└── stats/               statistiques
docker/                  configuration rspamd et unbound
scripts/                 sauvegarde de training_data.json
```
