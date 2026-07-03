# ==============================================================================
# CodeSleuth — Dockerfile
# Build multi-stage pour une image de production optimisee.
# ==============================================================================

# ---- Stage 1 : Builder (installe les dependances) ----
FROM python:3.12-slim AS builder

WORKDIR /app

# Copier uniquement les fichiers de dependances en premier pour beneficier du cache Docker
COPY pyproject.toml ./

# Installer uv pour une gestion rapide des paquets
RUN pip install --no-cache-dir uv

# Installer les dependances dans un dossier dedie
RUN uv pip install --system --no-cache \
    google-adk>=2.3.0 \
    httpx>=0.28.1 \
    mcp>=1.28.1 \
    pygithub>=2.9.1 \
    python-dotenv>=1.2.2 \
    radon>=6.0.1

# ---- Stage 2 : Runner (image finale legere) ----
FROM python:3.12-slim AS runner

WORKDIR /app

# Copier les dependances installees depuis le builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copier le code source du projet
COPY codesleuth/ ./codesleuth/
COPY main.py ./

# Variables d'environnement par defaut (a surcharger via -e ou Secret Manager)
ENV CODESLEUTH_MODEL=gemini-2.5-flash
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Le port utilise par l'ADK API server (Cloud Run attend 8080)
EXPOSE 8080

# Lancer le serveur ADK
CMD ["python", "-m", "google.adk.cli", "api_server", "--port", "8080", "--allow_origins", "*", "codesleuth"]
