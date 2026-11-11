# =============================================================================
# VantaVisionAI — Enterprise Multi-Device AI Security Intelligence Platform
# Production Multi-Runtime Dockerfile (Python FastAPI + Node.js Unified Server)
# =============================================================================
FROM python:3.11-slim

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    DATABASE_PATH=/app/data/vanta_vision.db \
    ENVIRONMENT=production \
    GEMINI_LIVE_MODEL=gemini-3.8-live \
    GEMINI_REASONING_MODEL=gemini-3.8-flash \
    GEMINI_TTS_MODEL=gemini-3.8-flash-tts \
    GEMINI_TTS_LITE_MODEL=gemini-3.8-flash-lite-tts \
    GEMINI_TRANSCRIBE_MODEL=gemini-3.5-transcribe

WORKDIR /app

# Install system dependencies (curl for container healthchecks, nodejs for hybrid scripts)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Python backend dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy package manifests and install Node runtime dependencies
COPY package.json ./
RUN npm install --omit=dev --ignore-scripts || true

# Copy application source code
COPY backend ./backend
COPY static ./static
COPY index.html ./index.html
COPY dev-server.cjs ./dev-server.cjs
COPY main.py ./main.py
COPY firebase-applet-config.json ./firebase-applet-config.json
COPY firebase-blueprint.json ./firebase-blueprint.json
COPY firestore.rules ./firestore.rules

# Create persistent data directory and non-root operator user
RUN mkdir -p /app/data && \
    useradd -m -u 10001 vantauser && \
    chown -R vantauser:vantauser /app

USER vantauser

EXPOSE 8000 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
