FROM python:3.11-slim

# ======== системные зависимости ========
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ======== Python-зависимости ========
COPY requirements.txt .
RUN pip install --no-cache-dir uv
RUN uv pip install --system -r requirements.txt
RUN uv pip install --system semgrep

# ======== агент ========
COPY agent.py .
COPY tools/ ./tools/
COPY rules/ ./rules/
COPY prompts/ ./prompts/
COPY schemas/ ./schemas/

# ======== папка с отчетами ========
RUN mkdir -p /app/reports

# ======== настройка окружения ========
ENV PYTHONUNBUFFERED=1

# ======== запуск ========
CMD ["python", "-u", "agent.py", \
     "--url", "http://juice-shop:3000", \
     "--source", "/app/juice-shop", \
     "--rules", "/app/rules/rules_semgrep.yaml"]