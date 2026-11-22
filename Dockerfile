# ======== учебный контур LFI/RFI ========
FROM python:3.11-slim AS file-inclusion

WORKDIR /lab
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY target/LFI_RFI_service.py target/LFI_RFI_remote.py target/fi_private_page.py ./
COPY target/fi_pages/ ./fi_pages/

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LAB_HOST=0.0.0.0
USER 10001:10001
EXPOSE 5101 5102
CMD ["python", "LFI_RFI_service.py"]

# ======== агент (образ по умолчанию) ========
FROM python:3.11-slim AS agent

# ======== системные зависимости ========
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y docker.io

WORKDIR /app

# ======== nuclei (DAST) ========
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*

RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64) NUCLEI_ARCH="linux_amd64" ;; \
      arm64) NUCLEI_ARCH="linux_arm64" ;; \
      *) NUCLEI_ARCH="linux_amd64" ;; \
    esac && \
    NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d 'v') && \
    echo "Installing nuclei v${NUCLEI_VER} for ${NUCLEI_ARCH}" && \
    curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_${NUCLEI_ARCH}.zip" -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei && \
    nuclei -version

# ======== ffuf (fuzzing) ========
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64) FFUF_ARCH="linux_amd64" ;; \
      arm64) FFUF_ARCH="linux_arm64" ;; \
      *) FFUF_ARCH="linux_amd64" ;; \
    esac && \
    FFUF_VER="2.1.0" && \
    curl -sSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_${FFUF_ARCH}.tar.gz" -o /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin && \
    rm /tmp/ffuf.tar.gz && \
    chmod +x /usr/local/bin/ffuf && \
    ffuf -V

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

# ======== папка со стандартными путями ========
RUN mkdir -p /app/tools/wordlists && \
    curl -sSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
    -o /app/tools/wordlists/hidden_paths.txt && \
    test -s /app/tools/wordlists/hidden_paths.txt

# ======== настройка окружения ========
ENV PYTHONUNBUFFERED=1

# ======== запуск ========
CMD ["python", "-u", "agent.py", \
     "--url", "http://juice-shop:3000", \
     "--source", "/app/juice-shop", \
     "--rules", "/app/rules/rules_semgrep.yaml"]