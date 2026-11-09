from langchain.tools import tool
import requests
import json

@tool
def http_request_with_auth(
    method: str,
    url: str,
    token: str,
    body: str = "",
    headers: str = "{}",
) -> str:
    """
    HTTP-запрос с автоматической подстановкой Bearer-токена.

    method — HTTP-метод
    url — полный URL
    token — токен авторизации
    body — тело запроса (опционально)
    headers — дополнительные заголовки в виде JSON-строки

    Возвращает статус и тело ответа.
    """
    try:
        extra = json.loads(headers) if headers else {}
    except json.JSONDecodeError:
        return "ошибка: headers должен быть валидным JSON"

    headers_dict = {
        "Authorization": f"Bearer {token}",
        **extra,
    }

    method = method.upper()
    try:
        res = requests.request(
            method=method,
            url=url,
            headers=headers_dict,
            data=body if body else None,
            timeout=15,
            allow_redirects=True,
        )
        return (
            f"status={res.status_code}\n"
            f"body={res.text[:2000]}"
        )
    except Exception as e:
        return f"ошибка запроса: {e}"