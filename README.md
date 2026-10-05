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