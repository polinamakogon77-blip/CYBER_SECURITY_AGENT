# ======== учебный контур LFI/RFI ========
FROM python:3.11-slim AS file-inclusion

WORKDIR /lab

# Python-зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Файлы LFI/RFI
COPY target/LFI_RFI_service.py ./
COPY target/LFI_RFI_remote.py ./
COPY target/fi_private_page.py ./
COPY target/fi_pages/ ./fi_pages/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LAB_HOST=0.0.0.0

# Создаем пользователя и назначаем права на рабочую директорию
RUN useradd -u 10001 -m -s /bin/bash labuser && \
    chown -R 10001:10001 /lab

USER 10001:10001

EXPOSE 5101 5102
CMD ["python", "LFI_RFI_service.py"]


# ======== основной AI-агент ========
FROM python:3.11-slim AS agent

# Системные зависимости
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        ca-certificates \
        unzip \
        docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Установка Nuclei
RUN set -eu; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64) NUCLEI_ARCH="linux_amd64" ;; \
      arm64) NUCLEI_ARCH="linux_arm64" ;; \
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;; \
    esac; \
    NUCLEI_VER=$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | head -n 1 | cut -d '"' -f4 | tr -d 'v'); \
    test -n "$NUCLEI_VER"; \
    echo "Installing Nuclei v${NUCLEI_VER}"; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_${NUCLEI_ARCH}.zip" -o /tmp/nuclei.zip; \
    unzip -oq /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    rm /tmp/nuclei.zip; \
    chmod +x /usr/local/bin/nuclei; \
    nuclei -version

# Установка ffuf
RUN set -eu; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64) FFUF_ARCH="linux_amd64" ;; \
      arm64) FFUF_ARCH="linux_arm64" ;; \
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;; \
    esac; \
    FFUF_VER="2.1.0"; \
    echo "Installing ffuf v${FFUF_VER}"; \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_${FFUF_ARCH}.tar.gz" -o /tmp/ffuf.tar.gz; \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf; \
    rm /tmp/ffuf.tar.gz; \
    chmod +x /usr/local/bin/ffuf; \
    ffuf -V

# Python-зависимости
COPY requirements.txt .
RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
RUN pip install semgrep -i https://pypi.tuna.tsinghua.edu.cn/simple

# Копирование кода агента
COPY cyber_agent/ ./cyber_agent/
COPY rules/ ./rules/
COPY agent_plugin.py ./agent_plugin.py
COPY plugins/ ./plugins/

# Словарь для ffuf
RUN mkdir -p /app/tools/wordlists && \
    curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
    -o /app/tools/wordlists/hidden_paths.txt && \
    test -s /app/tools/wordlists/hidden_paths.txt

# Папка с отчётами
RUN mkdir -p /app/reports && chmod 777 /app/reports

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Запуск агента 
CMD ["python", "-u", "-m", "cyber_agent.agent.cli.main", \
     "--url", "http://juice-shop:3000", \
     "--source", "/app/juice-shop", \
     "--rules", "/app/rules/rules_semgrep.yaml"]