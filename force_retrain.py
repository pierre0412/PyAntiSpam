#!/usr/bin/env python3
"""Script pour forcer le réentraînement ML avec les données existantes"""

import json
import sys
import logging
from pathlib import Path

# Import des modules PyAntiSpam
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from pyantispam.config import ConfigManager
from pyantispam.ml.ml_classifier import MLClassifier
from pyantispam.stats.stats_manager import StatsManager

def main():
    """Force le réentraînement ML avec les données de training_data.json"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    try:
        # Charger la configuration
        config_manager = ConfigManager()
        config = config_manager.config

        # Initialiser le classificateur ML
        ml_classifier = MLClassifier(config, data_dir="data")

        # Utiliser les données par défaut du classificateur
        logger.info("Utilisation des données d'entraînement par défaut")
        training_samples = ml_classifier.create_default_training_data()

        logger.info(f"Créé {len(training_samples)} échantillons d'entraînement par défaut")

        # Réentraîner le modèle
        logger.info("Démarrage du réentraînement ML...")
        result = ml_classifier.train_with_samples(training_samples)

        if result["success"]:
            logger.info(f"✅ Réentraînement réussi!")
            logger.info(f"   Précision: {result.get('accuracy', 0):.3f}")
            logger.info(f"   Échantillons: {result.get('samples_count', 0)}")
            logger.info(f"   Spam: {result.get('spam_count', 0)}")
            logger.info(f"   Ham: {result.get('ham_count', 0)}")

            # Mettre à jour les statistiques
            stats_manager = StatsManager()
            stats_manager.record_ml_retrain(result)

            return True
        else:
            logger.error(f"❌ Échec du réentraînement: {result.get('error', 'Erreur inconnue')}")
            return False

    except Exception as e:
        logger.error(f"Erreur lors du réentraînement forcé: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)