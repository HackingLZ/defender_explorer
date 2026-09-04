# Multi-stage Dockerfile for Defender Explorer
# Stage 1: Build frontend
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS frontend-build

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Build luadec from source
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS luadec-build

ARG LUADEC_COMMIT=895d92313fabaee260121c758c8320d1b21dd741
ARG LUA51_COMMIT=cdcfa70f2f731409046374e797a62314b4924b77

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    libreadline-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Fetch the reviewed luadec revision and its pinned Lua 5.1 submodule.
RUN git init /luadec \
    && git -C /luadec remote add origin https://github.com/viruscamp/luadec.git \
    && git -C /luadec fetch --depth 1 origin "${LUADEC_COMMIT}" \
    && git -C /luadec checkout --detach FETCH_HEAD \
    && test "$(git -C /luadec rev-parse HEAD)" = "${LUADEC_COMMIT}" \
    && git -C /luadec submodule update --init --depth 1 lua-5.1 \
    && test "$(git -C /luadec/lua-5.1 rev-parse HEAD)" = "${LUA51_COMMIT}" \
    && cd /luadec \
    && cd lua-5.1 \
    && make linux \
    && cd ../luadec \
    && make LUAVER=5.1

# Stage 3: Python backend with frontend static files
FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

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
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.txt

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
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
