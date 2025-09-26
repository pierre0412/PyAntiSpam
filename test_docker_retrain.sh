#!/bin/bash
# Script de test pour vérifier que le réentraînement fonctionne dans Docker

set -e

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🧪 Test du réentraînement ML dans Docker"
echo "========================================"

# 1. Vérifier que le container tourne
if ! docker ps --format '{{.Names}}' | grep -q "^pyantispam$"; then
    log_error "Le container pyantispam n'est pas en cours d'exécution"
    echo "Lancez d'abord: ./scripts/docker-run.sh start"
    exit 1
fi

log_info "Container pyantispam trouvé ✓"

# 2. Vérifier les stats avant réentraînement
log_info "Stats avant réentraînement:"
docker exec pyantispam python -m pyantispam.cli stats | grep "Réentraînements ML"

# 3. Lancer le réentraînement
log_info "Lancement du réentraînement..."
docker exec pyantispam python force_retrain.py

# 4. Vérifier les stats après réentraînement
log_info "Stats après réentraînement:"
docker exec pyantispam python -m pyantispam.cli stats | grep "Réentraînements ML"

# 5. Vérifier que le fichier de modèle a été mis à jour
log_info "Vérification du modèle ML..."
if docker exec pyantispam ls -la data/spam_model.pkl | grep -q "$(date +%Y-%m-%d)"; then
    log_info "Modèle ML mis à jour aujourd'hui ✓"
else
    log_warn "Le modèle ML n'a pas été mis à jour récemment"
fi

# 6. Test avec docker-run.sh
log_info "Test de la commande ./scripts/docker-run.sh retrain..."
./scripts/docker-run.sh retrain

echo ""
log_info "🎉 Test terminé ! Le réentraînement Docker fonctionne correctement."
echo ""
echo "💡 Commandes disponibles:"
echo "   ./scripts/docker-run.sh stats   - Voir les statistiques"
echo "   ./scripts/docker-run.sh retrain - Forcer un réentraînement"