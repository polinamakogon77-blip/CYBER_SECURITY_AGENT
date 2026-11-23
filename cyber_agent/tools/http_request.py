from langchain.tools import tool
import requests
import json

@tool
def http_request(
    method: str,
    url: str,
    headers: str = "{}",
    body: str = ""
) -> str:
    """
    Выполняет произвольный HTTP-запрос.

    method — HTTP-метод (GET, POST, PUT, DELETE, PATCH и т.д.)
    url — полный URL
    headers — JSON-строка с заголовками (по умолчанию {})
    body — тело запроса (строка, для JSON передавай как строку)

    Возвращает статус, заголовки ответа и тело (обрезанное).
    """
    try:
        headers_dict = json.loads(headers) if headers else {}
    except json.JSONDecodeError:
        return "ошибка: headers должен быть валидным JSON"

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
        resp_headers = dict(res.headers)
        body_preview = res.text[:2000] if res.text else ""
        return (
            f"status={res.status_code}\n"
            f"headers={json.dumps(resp_headers, ensure_ascii=False)}\n"
            f"body={body_preview}"
        )
    except Exception as e:
        return f"ошибка запроса: {e}"