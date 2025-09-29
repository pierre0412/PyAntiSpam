### Projet démarré en vibecoding et retouché à la main :)
# PyAntiSpam

Système intelligent de détection et filtrage automatique des spams par email utilisant un pipeline en 3 étapes : listes manuelles, machine learning et LLM.
Le script peut tourner en continu ou être lancé ponctuellement. Il peut être utilisé seul ou tourner dans un container Docker (voir README-docker.md et /scripts/docker-run.sh)

## Fonctionnalités

### ✅ Détection Multi-Niveaux
- **🥇 Whitelist/Blacklist** : Contrôle manuel prioritaire (emails et domaines entiers)
- **🥈 Machine Learning** : Random Forest avec 40+ features (mots-clés, structure, domaines suspects)
- **🥉 Large Language Models** : OpenAI GPT et Anthropic Claude pour les cas complexes

### ✅ Gestion Avancée des Listes
- **Auto-détection** : emails vs domaines automatiquement
- **Validation** : normalisation et vérification des entrées
- **Import/Export** : sauvegarde et restauration des listes
- **Domaines entiers** : `example.com` bloque tous les `*@example.com`

### ✅ Multi-Comptes & IMAP
- **Support multi-serveurs** : Gmail, Outlook, serveurs personnalisés tant que c'est de l'IMAP
- **Gestion dossiers** : création automatique avec conventions IMAP
- **Traitement robuste** : gestion des erreurs et emails supprimés
- **Nettoyage automatique** : suppression des anciens spams après X jours

### ✅ Configuration Flexible
- **YAML** : configuration principale centralisée
- **Variables d'environnement** : clés API et mots de passe sécurisés
- **Seuils ajustables** : confiance ML, utilisation LLM

### ✅ Statistiques & Monitoring
- **Tracking complet** : emails traités, spams détectés, méthodes utilisées
- **Apprentissage suivi** : feedback traité, échantillons ML, réentraînements
- **Performance mesurée** : temps de traitement, erreurs, efficacité
- **Historique quotidien** : activité des derniers jours
- **Export des données** : sauvegarde et analyse avancée

### ✅ Apprentissage par Feedback
- **Dossiers spéciaux** : correction facile via votre client email
- **Auto-apprentissage** : whitelist/blacklist et amélioration ML
- **Routage intelligent** : emails corrigés placés correctement
- **Réentraînement automatique** : modèle ML s'améliore en continu

## Installation

```bash
# Cloner le projet
git clone https://github.com/pierre0412/PyAntiSpam.git
cd PyAntiSpam

# Créer environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -e .
```

## Configuration

### 1. Configuration initiale

```bash
# Configuration initiale (crée config.yaml et .env)
pyantispam setup

# Tester la configuration
pyantispam test-config
```

### 2. Configuration email (`config.yaml`)

```yaml
# Comptes email
email_accounts:
  - name: "personal"
    server: "mail.example.com"
    port: 993
    username: "votre-email@example.com"
    password_env: "EMAIL_PASSWORD_PERSONAL"  # Variable dans .env
    use_ssl: true

# Paramètres de détection
detection:
  ml_confidence_threshold: 0.8    # Seuil ML (0.0-1.0) 0 incertain, 1 confiance absolue
  use_llm_for_uncertain: true     # Utiliser LLM si ML incertain
  classify_marketing_as_spam: true # Classify unsolicited marketing/newsletters as spam
  marketing_confidence_threshold: 0.6  # Lower threshold for marketing classification

# Configuration LLM
llm:
  provider: "openai"              # openai ou anthropic
  openai_model: "gpt-5-nano"  # ou gpt-4.1-nano
  anthropic_model: "claude-3-haiku-20240307"

# Actions
actions:
  move_spam_to_folder: "SPAM_AUTO"  # Dossier de destination
  auto_delete_after_days: 10        # Suppression auto des spams après X jours (0 = jamais)
```

### 3. Variables d'environnement (`.env`)

```bash
# Mots de passe email
EMAIL_PASSWORD_PERSONAL=votre-mot-de-passe

# Clés API LLM (optionnel)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
```

### 4. Machine Learning

Le système ML s'initialise automatiquement avec des exemples par défaut. Le modèle Random Forest analyse :

**Features extraites (40+) :**
- **Structure** : longueur sujet/contenu, ratio majuscules, ponctuation
- **Mots-clés spam** : urgence, argent, phishing, marketing, arnaques
- **URLs & liens** : nombre, domaines suspects (.tk, .ml, .ga, etc.)
- **Expéditeur** : domaine légitime, caractères spéciaux, longueur
- **Contenu** : HTML, numéros de téléphone, adresses email

**Configuration ML avancée :**
```yaml
detection:
  ml_confidence_threshold: 0.8    # Plus élevé = plus strict

learning:
  retrain_threshold: 10           # Ré-entraîner après N nouveaux exemples
```

## Utilisation

### Commandes principales

```bash
# Scan unique
pyantispam run

# Mode daemon (continu)
pyantispam daemon

# Scan d'un compte spécifique
pyantispam run --account personal

# Mode dry-run (test)
pyantispam run --dry-run
```

### Gestion des listes (Whitelist/Blacklist)

```bash
# Whitelist - Emails spécifiques
pyantispam whitelist add important@company.com
pyantispam whitelist add support@github.com

# Whitelist - Domaines entiers
pyantispam whitelist add company.com        # Tous les @company.com
pyantispam whitelist add microsoft.com
pyantispam whitelist add google.com

# Blacklist - Domaines suspects
pyantispam blacklist add suspicious-site.tk
pyantispam blacklist add spam-domain.ml
pyantispam blacklist add lottery-scam.ga

# Gestion des listes
pyantispam whitelist list                   # Voir whitelist
pyantispam blacklist list                   # Voir blacklist
pyantispam whitelist remove example.com     # Supprimer
pyantispam blacklist remove badsite.com

# Import/Export (sauvegarde)
pyantispam whitelist export whitelist_backup.json
pyantispam blacklist import blacklist.txt
```

### Pipeline de détection

Le système traite les emails dans cet ordre :

1. **🥇 Whitelist** → ✅ GARDER immédiatement (confiance: 1.0)
2. **🥇 Blacklist** → ❌ SPAM immédiatement (confiance: 1.0)
3. **🥈 Machine Learning** → Si confiance > seuil (0.8), décision finale
4. **🥉 LLM** → Pour les cas incertains du ML
5. **Défaut** → ✅ GARDER si tout incertain

### Apprentissage par feedback

Corrigez facilement les erreurs en déplaçant les emails vers des dossiers spéciaux :

```bash
# Votre client email crée automatiquement ces dossiers :
INBOX.PYANTISPAM_WHITELIST   # → Ajoute expéditeur à whitelist + email dans INBOX
INBOX.PYANTISPAM_BLACKLIST   # → Ajoute expéditeur à blacklist + email dans spam
INBOX.PYANTISPAM_NOT_SPAM    # → Corrige ML (faux positif) + email dans INBOX
INBOX.PYANTISPAM_IS_SPAM     # → Corrige ML (spam manqué) + email dans spam

# Traitement automatique des corrections
pyantispam run              # Traite aussi les feedbacks automatiquement
```

### Statistiques et monitoring

```bash
# Statistiques complètes
pyantispam stats

# Détails quotidiens
pyantispam stats --daily
pyantispam stats --daily --days 30

# Export des statistiques
pyantispam stats --export backup_stats.json

# Statut des listes
pyantispam status
```

## Architecture

```
├── src/pyantispam/
│   ├── config/          # ✅ Gestion configuration YAML + .env
│   ├── email/           # ✅ Client IMAP robuste + traitement emails
│   ├── filters/         # ✅ Whitelist/blacklist avec validation
│   ├── ml/              # ✅ Random Forest + extraction features
│   ├── llm/             # ✅ OpenAI GPT + Anthropic Claude
│   ├── stats/           # ✅ Tracking et export des statistiques
│   ├── learning/        # ✅ Apprentissage par feedback utilisateur
│   └── cli.py           # ✅ Interface ligne de commande complète
├── data/                # ✅ Listes + modèles ML persistants
│   ├── whitelist.json   # ✅ Emails et domaines autorisés
│   ├── blacklist.json   # ✅ Emails et domaines bloqués
│   ├── spam_model.pkl   # ✅ Modèle ML entraîné
│   ├── feature_scaler.pkl # ✅ Normalisation features
│   ├── spam_stats.json  # ✅ Statistiques de détection et apprentissage
│   └── training_data.json # ✅ Données d'entraînement ML
├── config.yaml          # ✅ Configuration principale
└── .env                 # ✅ Clés API et mots de passe
```

### Pipeline de traitement

```
Email entrant
    ↓
┌─────────────────┐
│   Whitelist?    │ → OUI → ✅ GARDER (confiance: 1.0)
└─────────────────┘
    ↓ NON
┌─────────────────┐
│   Blacklist?    │ → OUI → ❌ SPAM (confiance: 1.0)
└─────────────────┘
    ↓ NON
┌─────────────────┐
│ ML > seuil?     │ → OUI → ✅/❌ Décision ML
└─────────────────┘
    ↓ NON (incertain)
┌─────────────────┐
│ LLM activé?     │ → OUI → 🤖 Analyse LLM
└─────────────────┘
    ↓ NON
✅ GARDER (par défaut)
```

## Référence des commandes

### Commandes principales
```bash
# Traitement des emails
pyantispam run                              # Scan une fois + traite feedbacks + nettoyage auto
pyantispam run --dry-run                    # Test sans actions (pas de nettoyage)
pyantispam run --account personal           # Compte spécifique
pyantispam daemon                           # Mode continu avec nettoyage périodique

# Statistiques et monitoring
pyantispam stats                            # Statistiques complètes
pyantispam stats --daily                    # Détails quotidiens
pyantispam stats --export stats.json       # Export des données
pyantispam status                           # État du système

# Configuration
pyantispam setup                            # Configuration initiale
pyantispam test-config                      # Tester la configuration
```

### Gestion automatique des spams

Le système effectue un **nettoyage automatique** des anciens spams à chaque exécution :

```yaml
# config.yaml
actions:
  move_spam_to_folder: "SPAM_AUTO"     # Dossier de destination des spams
  auto_delete_after_days: 10           # Suppression automatique après 10 jours
```

**Comportements :**
- `auto_delete_after_days: 10` → Supprime les spams > 10 jours du dossier spam
- `auto_delete_after_days: 0` → Désactive le nettoyage automatique (conservation infinie)
- Le nettoyage s'exécute **avant** le traitement des nouveaux emails
- Affichage CLI : `🧹 Old spam deleted: X` si des emails sont supprimés

### Gestion whitelist
```bash
pyantispam whitelist add email@domain.com   # Ajouter email
pyantispam whitelist add domain.com         # Ajouter domaine
pyantispam whitelist remove email@domain.com # Supprimer
pyantispam whitelist list                   # Lister
pyantispam whitelist clear --confirm        # Vider (dangereux)
pyantispam whitelist export backup.json    # Exporter
pyantispam whitelist import backup.json    # Importer
```

### Gestion blacklist
```bash
pyantispam blacklist add spam@bad.com       # Ajouter email
pyantispam blacklist add suspicious.tk     # Ajouter domaine
pyantispam blacklist remove spam@bad.com   # Supprimer
pyantispam blacklist list                  # Lister
pyantispam blacklist clear --confirm       # Vider (dangereux)
pyantispam blacklist export backup.json   # Exporter
pyantispam blacklist import backup.json   # Importer
```

### Statistiques détaillées
```bash
# Vue d'ensemble
pyantispam stats                           # Toutes les statistiques

# Détails temporels
pyantispam stats --daily                   # Activité quotidienne (7 jours)
pyantispam stats --daily --days 30         # Activité sur 30 jours

# Export et sauvegarde
pyantispam stats --export rapport.json     # Export complet
pyantispam stats --export data/backup.json # Sauvegarde dans data/
```

### Informations trackées
```bash
# 🔍 Détection
#   - Emails traités (total, spam, ham)
#   - Méthodes utilisées (whitelist, ML, LLM)
#   - Distribution de confiance
#   - Taux de détection

# 📚 Apprentissage
#   - Feedback traité par type
#   - Ajouts whitelist/blacklist
#   - Échantillons ML collectés
#   - Réentraînements effectués

# ⚡ Performance
#   - Temps de traitement moyen
#   - Erreurs rencontrées
#   - Efficacité par méthode
#   - Historique quotidien
```

## Développement

### ✅ Fonctionnalités implémentées
- **Configuration YAML** : gestion centralisée avec validation
- **Client IMAP robuste** : gestion erreurs, conventions serveurs
- **Pipeline 3 niveaux** : listes → ML → LLM avec fallbacks
- **ML Random Forest** : 40+ features, auto-initialisation
- **LLM multi-providers** : OpenAI + Anthropic avec prompts optimisés
- **CLI complète** : toutes les opérations via ligne de commande

### 🚧 Extensions possibles
- **Interface web** : dashboard pour monitoring et configuration
- **API REST** : intégration avec autres systèmes
- **Modèles ML avancés** : BERT, transformers pour texte
- **Règles personnalisées** : filtres utilisateur scriptables
- **Notifications** : alertes sur détections importantes
- **Métriques** : statistiques et performance des modèles

## Licence

MIT

## 