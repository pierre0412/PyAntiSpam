#!/bin/bash
# Script helper pour lancer PyAntiSpam avec Docker

set -e

# Configuration
IMAGE_NAME="pyantispam:latest"
CONTAINER_NAME="pyantispam"
DATA_DIR="./data"
LOGS_DIR="./logs"
CONFIG_FILE="./config.yaml"
ENV_FILE="./.env"

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonctions helper
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier les prérequis
check_prerequisites() {
    log_info "Vérification des prérequis..."

    # Docker installé ?
    if ! command -v docker &> /dev/null; then
        log_error "Docker n'est pas installé ou accessible"
        exit 1
    fi

    # docker-compose installé ?
    if ! command -v docker-compose &> /dev/null; then
        log_warn "docker-compose n'est pas installé, utilisation de 'docker run'"
        USE_COMPOSE=false
    else
        USE_COMPOSE=true
    fi

    # Fichiers de configuration
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Fichier de configuration manquant: $CONFIG_FILE"
        log_info "Lancez d'abord: pyantispam setup"
        exit 1
    fi

    if [[ ! -f "$ENV_FILE" ]]; then
        log_warn "Fichier .env manquant, création d'un fichier vide"
        touch "$ENV_FILE"
    fi

    # Créer les répertoires nécessaires
    mkdir -p "$DATA_DIR" "$LOGS_DIR"

    log_info "Prérequis OK ✓"
}

# Construire l'image Docker
build_image() {
    log_info "Construction de l'image Docker..."
    docker build -t "$IMAGE_NAME" .
    log_info "Image construite: $IMAGE_NAME ✓"
}

# Lancer avec docker-compose
run_with_compose() {
    log_info "Lancement avec docker-compose..."
    docker-compose up -d
    log_info "Container démarré ✓"

    # Afficher les logs pendant quelques secondes
    log_info "Affichage des logs (Ctrl+C pour arrêter):"
    docker-compose logs -f --tail=50
}

# Lancer avec docker run
run_with_docker() {
    log_info "Lancement avec docker run..."

    # Arrêter le container s'il existe déjà
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "Arrêt du container existant..."
        docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
        docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi

    # Lancer le nouveau container
    docker run -d \
        --name "$CONTAINER_NAME" \
        --restart unless-stopped \
        -v "$(pwd)/$CONFIG_FILE:/app/config.yaml:ro" \
        -v "$(pwd)/$ENV_FILE:/app/.env:ro" \
        -v "$(pwd)/$DATA_DIR:/app/data" \
        -v "$(pwd)/$LOGS_DIR:/app/logs" \
        "$IMAGE_NAME"

    log_info "Container démarré: $CONTAINER_NAME ✓"

    # Afficher les logs
    log_info "Affichage des logs (Ctrl+C pour arrêter):"
    docker logs -f --tail=50 "$CONTAINER_NAME"
}

# Fonction principale
main() {
    local command="${1:-start}"

    case "$command" in
        "build")
            check_prerequisites
            build_image
            ;;
        "start"|"run")
            check_prerequisites
            build_image
            if [[ "$USE_COMPOSE" == "true" ]]; then
                run_with_compose
            else
                run_with_docker
            fi
            ;;
        "stop")
            if [[ "$USE_COMPOSE" == "true" ]] && [[ -f "docker-compose.yml" ]]; then
                docker-compose stop
            else
                docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
            fi
            log_info "Container arrêté ✓"
            ;;
        "logs")
            if [[ "$USE_COMPOSE" == "true" ]] && [[ -f "docker-compose.yml" ]]; then
                docker-compose logs -f --tail=100
            else
                docker logs -f --tail=100 "$CONTAINER_NAME"
            fi
            ;;
        "shell")
            if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
                docker exec -it "$CONTAINER_NAME" bash
            else
                log_error "Container $CONTAINER_NAME n'est pas en cours d'exécution"
                exit 1
            fi
            ;;
        "stats")
            if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
                docker exec "$CONTAINER_NAME" python -m pyantispam.cli stats
            else
                log_error "Container $CONTAINER_NAME n'est pas en cours d'exécution"
                exit 1
            fi
            ;;
        "help"|*)
            echo "Usage: $0 {build|start|stop|logs|shell|stats|help}"
            echo ""
            echo "Commandes:"
            echo "  build  - Construire l'image Docker"
            echo "  start  - Démarrer PyAntiSpam en mode daemon"
            echo "  stop   - Arrêter le container"
            echo "  logs   - Afficher les logs en temps réel"
            echo "  shell  - Ouvrir un shell dans le container"
            echo "  stats  - Afficher les statistiques"
            echo "  help   - Afficher cette aide"
            ;;
    esac
}

# Exécuter la fonction principale avec tous les arguments
main "$@"
