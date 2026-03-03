FROM python:3.11-slim

WORKDIR /app

# Install build dependencies including git for luadec
RUN apt-get update && apt-get install -y \
    build-essential \
    cabextract \
    yara \
    git \
    libreadline-dev \
    && rm -rf /var/lib/apt/lists/*

# Build luadec 5.1 from source
RUN git clone https://github.com/viruscamp/luadec.git /tmp/luadec && \
    cd /tmp/luadec && \
    git submodule update --init lua-5.1 && \
    cd lua-5.1 && \
    make linux && \
    cd ../luadec && \
    make LUAVER=5.1 && \
    cp luadec /usr/local/bin/luadec && \
    rm -rf /tmp/luadec

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app
ENV YARA_RULES_PATH=/data/extracted/yara
ENV LUADEC_PATH=/usr/local/bin/luadec

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
