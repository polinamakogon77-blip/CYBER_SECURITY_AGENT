# проверка на IDOR
from langchain.tools import tool
import requests


@tool
def check_idor(url: str, endpoint: str, id_object: str, token: str):
    """
    проверяет, может ли пользователь получить доступ к данным, 
    даже если не является их владельцом

    url - адрес ресурса
    endpoint - точка входа
    id_object - индикатор объекта
    token - токен пользователя

    отправляет get-запрос к url/endpoint/id_object c bearer token 
    возвращает статус
    """
    url = f"{url}{endpoint}/{id_object}"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        res = requests.get(url, headers=headers, timeout=5)
        verdict = "найдена уязвимость IDOR" if res.status_code == 200 else "ОК"

        return f"{verdict}"
    except Exception as e:
        return f"ошибка запроса {e}"
