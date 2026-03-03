# Multi-stage Dockerfile for Defender Explorer
# Stage 1: Build frontend
FROM node:20-alpine AS frontend-build

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Build luadec from source
FROM debian:bookworm-slim AS luadec-build

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    libreadline-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clone and build luadec for Lua 5.1
RUN git clone https://github.com/viruscamp/luadec.git /luadec \
    && cd /luadec \
    && git submodule update --init lua-5.1 \
    && cd lua-5.1 \
    && make linux \
    && cd ../luadec \
    && make LUAVER=5.1

# Stage 3: Python backend with frontend static files
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (libyara-dev for yara-python, weasyprint deps for PDF export)
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara \
    libyara-dev \
    libreadline8 \
    cabextract \
    gcc \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# Copy luadec binary from build stage
COPY --from=luadec-build /luadec/luadec/luadec /usr/local/bin/luadec
RUN chmod +x /usr/local/bin/luadec

# Copy backend requirements and install
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ .

# Copy defender_sig_extractor package
COPY defender_sig_extractor/ /app/defender_sig_extractor/

# Ensure defender_sig_extractor is importable
ENV PYTHONPATH=/app

# Copy built frontend from stage 1
COPY --from=frontend-build /frontend/dist /app/static

# Create non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
