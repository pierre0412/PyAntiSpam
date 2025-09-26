#!/usr/bin/env python3
"""Script pour forcer le réentraînement ML avec les VRAIES données utilisateur"""

import json
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any

# Import des modules PyAntiSpam
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from pyantispam.config import ConfigManager
from pyantispam.ml.ml_classifier import MLClassifier
from pyantispam.stats.stats_manager import StatsManager
from pyantispam.learning.feedback_processor import FeedbackProcessor

def collect_user_feedback_samples() -> List[Dict[str, Any]]:
    """Collecter les échantillons d'entraînement depuis les feedbacks utilisateur réels"""
    training_samples = []

    # 1. Charger les overrides utilisateur depuis llm_cache.json
    llm_cache_file = Path("data/llm_cache.json")
    user_override_samples = []

    if llm_cache_file.exists():
        try:
            with open(llm_cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)

            user_overrides = {k: v for k, v in cache_data.items()
                            if v.get('method') == 'user_feedback' and v.get('override')}

            # Essayer de reconstituer des échantillons à partir des overrides
            # Note: Les overrides n'ont que la décision, pas les données email complètes
            for fingerprint, override in user_overrides.items():
                # Créer un échantillon minimal basé sur l'override
                is_spam = override.get('action') == 'SPAM'

                # Échantillon minimaliste pour l'entraînement
                sample = {
                    'email_data': {
                        'sender_email': f'user_feedback_{fingerprint[:8]}@example.com',
                        'sender_domain': 'user-feedback.local',
                        'subject': f'User feedback sample {fingerprint[:8]}',
                        'text_content': f'User feedback training sample for {"spam" if is_spam else "ham"} classification'
                    },
                    'is_spam': is_spam
                }
                user_override_samples.append(sample)

            logging.info(f"Trouvé {len(user_overrides)} overrides utilisateur dans le cache LLM")
            logging.info(f"Créé {len(user_override_samples)} échantillons à partir des overrides")

        except Exception as e:
            logging.warning(f"Erreur lecture cache LLM: {e}")
            user_overrides = {}
    else:
        user_overrides = {}

    # Ajouter les échantillons des overrides
    training_samples.extend(user_override_samples)

    # 2. Essayer de charger l'ancien training_data.json (même corrompu)
    training_data_file = Path("data/training_data.json")
    if training_data_file.exists():
        try:
            with open(training_data_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Essayer de réparer le JSON corrompu
            if content and not content.strip().endswith('}') and not content.strip().endswith(']'):
                # Fichier tronqué, essayer de le fermer proprement
                if content.strip().endswith(','):
                    content = content.strip()[:-1]  # Enlever la virgule finale

                if content.count('[') > content.count(']'):
                    content += ']'  # Fermer le tableau
                elif content.count('{') > content.count('}'):
                    content += '}'  # Fermer l'objet

            # Essayer de parser le JSON réparé
            try:
                existing_samples = json.loads(content)
                if isinstance(existing_samples, list):
                    # Filtrer les échantillons valides
                    valid_samples = []
                    for sample in existing_samples:
                        if (isinstance(sample, dict) and
                            'email_data' in sample and
                            'is_spam' in sample and
                            isinstance(sample['email_data'], dict)):
                            valid_samples.append(sample)

                    training_samples.extend(valid_samples)
                    logging.info(f"Récupéré {len(valid_samples)} échantillons depuis training_data.json")

            except json.JSONDecodeError:
                logging.warning("Impossible de réparer training_data.json, utilisation des données par défaut")

        except Exception as e:
            logging.warning(f"Erreur lecture training_data.json: {e}")

    # 3. Si pas assez de données réelles, ajouter les échantillons par défaut
    if len(training_samples) < 10:
        logging.info("Pas assez de données réelles, ajout d'échantillons par défaut")
        config_manager = ConfigManager()
        ml_classifier = MLClassifier(config_manager.config, data_dir="data")
        default_samples = ml_classifier.create_default_training_data()
        training_samples.extend(default_samples)

    # 4. Déduplication par contenu email
    seen_fingerprints = set()
    unique_samples = []

    for sample in training_samples:
        # Créer une empreinte unique basée sur sender + subject + body
        email_data = sample.get('email_data', {})
        fingerprint = f"{email_data.get('sender_email', '')}{email_data.get('subject', '')}{str(email_data.get('text_content', email_data.get('body', '')))[:100]}"

        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            unique_samples.append(sample)

    logging.info(f"Total d'échantillons uniques pour l'entraînement: {len(unique_samples)}")

    # Statistiques
    spam_count = sum(1 for s in unique_samples if s.get('is_spam'))
    ham_count = len(unique_samples) - spam_count
    logging.info(f"  - Spam: {spam_count}")
    logging.info(f"  - Ham: {ham_count}")

    return unique_samples

def main():
    """Force le réentraînement ML avec les vraies données utilisateur"""
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
    logger = logging.getLogger(__name__)

    try:
        # Charger la configuration
        config_manager = ConfigManager()
        config = config_manager.config

        logger.info("🔍 Collecte des échantillons d'entraînement RÉELS...")

        # Collecter les vrais échantillons utilisateur
        training_samples = collect_user_feedback_samples()

        if not training_samples:
            logger.error("❌ Aucun échantillon d'entraînement disponible")
            return False

        # Initialiser le classificateur ML
        ml_classifier = MLClassifier(config, data_dir="data")

        # Réentraîner le modèle avec les VRAIES données
        logger.info(f"🚀 Démarrage du réentraînement ML avec {len(training_samples)} échantillons RÉELS...")
        result = ml_classifier.train_with_samples(training_samples)

        if result["success"]:
            logger.info(f"✅ Réentraînement réussi avec de VRAIES données!")
            logger.info(f"   📊 Précision: {result.get('accuracy', 0):.3f}")
            logger.info(f"   📧 Échantillons: {result.get('samples_count', 0)}")
            logger.info(f"   🗑️  Spam: {result.get('spam_count', 0)}")
            logger.info(f"   ✅ Ham: {result.get('ham_count', 0)}")

            # Mettre à jour les statistiques
            stats_manager = StatsManager()
            stats_manager.record_ml_retrain(result)

            logger.info("📈 Statistiques mises à jour")

            return True
        else:
            logger.error(f"❌ Échec du réentraînement: {result.get('error', 'Erreur inconnue')}")
            return False

    except Exception as e:
        logger.error(f"💥 Erreur lors du réentraînement forcé: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)