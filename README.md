# CYBER_SECURITY_AGENT
## __О проекте__

Разработка AI-агента для автоматического анализа веб-приложений на уязвимости.

## __Запуск через Docker__
### 1. Клонировать репозиторий
```bash
git clone https://github.com/polinamakogon77blip/CYBER_SECURITY_AGENT.git
cd CYBER_SECURITY_AGENT
```
### 2. Создайть файл .env в корне проекта, добавить NSU_TOKEN=''
### 3. Запустить
```bash
docker compose up --build
```
### 4. Остановить
```bash
docker compose down
```
### Запуск только juice-shop
```bash
docker compose up juice-shop
```
будет доступен на `http://localhost:3000`

### Запуск агента со своей задачей без зависимостей
```bash
docker compose run --rm --no-deps agent \
  python -u agent.py \
  --task "Проверь /app/target на SSRF."
```

### Только статический анализ
```bash
docker compose run --rm --no-deps agent \
  python -u agent.py \
  --task "Проверь /app/target. С помощью list_files прочитай список файлов, запусти Semgrep с p/python."
```

## __Запуск без Docker__
### 1. Клонировать репозиторий
```bash
git clone https://github.com/polinamakogon77blip/CYBER_SECURITY_AGENT.git
cd CYBER_SECURITY_AGENT
```
### 2. Установка Python-зависимости 
создайте виртуальное окружение и установите пакеты
```bash
# создать venv
python3 -m venv .venv

# активировать venv
source .venv/bin/activate        

# установить зависимости
pip install -r requirements.txt
pip install semgrep
```
### 3. Скачать исходники juice-shop
```bash
git clone https://github.com/juice-shop/juice-shop.git
cd CYBER_SECURITY_AGENT
```
### 4. Запустить juice-shop
```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```
### 5. Создать файл .env в корне проекта, добавить NSU_TOKEN=''. 
Если хотите подключить LangSmith, добавьте: 
```bash
LANGSMITH_TRACING=true
LANGSMITH_ENDPOINT=https://api.smith.langchain.com
LANGSMITH_API_KEY=''
LANGSMITH_PROJECT="cyber_security_agent"
```
### 6. Запуск
из корня проекта
```bash
python3 agent.py
```

#### __Флаги агента__

| Флаг | Описание |
|---|---|
| `--url` | URL приложения |
| `--source` | Путь к исходникам |
| `--idor-endpoint` | Точка входа для IDOR |
| `--idor-id` | ID объекта для IDOR |
| `--idor-token` | Токен для IDOR |
| `--no-idor` | Не проверять IDOR |
| `--no-semgrep` | Не запускать Semgrep |
| `--task` | Произвольная задача (перекрывает остальное) |

## Справка
```bash
python3 agent.py --help
```

## URL + исходники + IDOR + Semgrep
```bash
python3 agent.py \
  --url http://localhost:3000 \
  --source juice-shop
```

## Только статический анализ исходников
```bash
python3 agent.py \
  --source juice-shop \
  --no-idor
```

## IDOR без Semgrep
```bash
python3 agent.py \
  --url http://localhost:3000 \
  --no-semgrep
```

## Свой произвольный запрос
```bash
python3 agent.py \
  --task "Проверь /app/target на уязвимости. Сначала используй list_files, потом Semgrep с p/python."
```

## Отключить отдельные проверки
```bash
# без IDOR
python3 agent.py --url http://localhost:3000 --no-idor

# без Semgrep
python3 agent.py --url http://localhost:3000 --no-semgrep

# без обоих
python3 agent.py --url http://localhost:3000 --no-idor --no-semgrep
```
## Переопределить параметры IDOR
```bash
python3 agent.py \
  --url http://localhost:3000 \
  --no-semgrep \
  --idor-endpoint /api/v1/orders \
  --idor-id 42 \
  --idor-token "xyz"
```