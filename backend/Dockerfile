FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS luadec-build

ARG LUADEC_COMMIT=895d92313fabaee260121c758c8320d1b21dd741
ARG LUA51_COMMIT=cdcfa70f2f731409046374e797a62314b4924b77

# Build luadec from immutable source revisions.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libreadline-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git init /luadec \
    && git -C /luadec remote add origin https://github.com/viruscamp/luadec.git \
    && git -C /luadec fetch --depth 1 origin "${LUADEC_COMMIT}" \
    && git -C /luadec checkout --detach FETCH_HEAD \
    && test "$(git -C /luadec rev-parse HEAD)" = "${LUADEC_COMMIT}" \
    && git -C /luadec submodule update --init --depth 1 lua-5.1 \
    && test "$(git -C /luadec/lua-5.1 rev-parse HEAD)" = "${LUA51_COMMIT}" \
    && make -C /luadec/lua-5.1 linux \
    && make -C /luadec/luadec LUAVER=5.1

FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    cabextract \
    yara \
    libreadline8 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=luadec-build /luadec/luadec/luadec /usr/local/bin/luadec

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.txt

RUN useradd --create-home --uid 1000 appuser
COPY --chown=appuser:appuser . .

ENV PYTHONPATH=/app
ENV YARA_RULES_PATH=/data/extracted/yara
ENV LUADEC_PATH=/usr/local/bin/luadec

EXPOSE 8000

USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
