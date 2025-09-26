FROM python:3.11-slim

# Variables d'environnement
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
# Fuseau horaire par défaut
ENV TZ=Europe/Paris

# Créer utilisateur non-root pour sécurité
RUN groupadd -r pyantispam && useradd -r -g pyantispam pyantispam

# Installer les dépendances système nécessaires (incl. tzdata) et configurer le fuseau horaire
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    gcc \
    g++ \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# Répertoire de travail
WORKDIR /app

# Copier les fichiers de projet essentiels et le code source avant installation
COPY pyproject.toml requirements.txt ./
COPY src/ ./src/
COPY force_retrain.py force_retrain_real.py ./

# Installer les dépendances Python et le paquet
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

# Créer les répertoires de données avec bonnes permissions
RUN mkdir -p /app/data /app/logs /app/config && \
    chown -R pyantispam:pyantispam /app

# Basculer vers utilisateur non-root
USER pyantispam

# Healthcheck pour monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import pyantispam; print('OK')" || exit 1

# Port d'exposition (pour future API web)
# EXPOSE 8000

# Commande par défaut - mode daemon
CMD ["python", "-m", "pyantispam.cli", "daemon"]
