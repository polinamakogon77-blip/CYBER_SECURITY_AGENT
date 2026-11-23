"""Tool: проверка отражённого XSS в параметре."""
import json
import requests
from langchain.tools import tool


@tool
def test_xss_reflected(target_url: str, param: str, payload: str = "<script>alert(1)</script>",
    method: str = "GET", extra_params: str = ""):
    """
    проверить параметр на отражённый XSS.

    отправляет запрос с payload в параметре и проверяет, отражается ли
    payload в теле ответа без экранирования.

    ВАЖНО: отражение payload — это факт. Он становится XSS-уязвимостью
    только если payload интерпретируется браузером как код (теги <>,
    обработчики onerror/onload, javascript: в href). Простое отражение
    текста без исполнения — это HTML injection, но не XSS.

    используй для проверки поля поиска, параметров фильтра, любых
    параметров, которые сервер отражает в ответе.

    target_url: полный URL эндпоинта, например "http://juice-shop:3000/rest/products/search"
    param: имя параметра, например "q"
    payload: XSS-payload (по умолчанию "<script>alert(1)</script>")
    method: "GET" или "POST"
    extra_params: дополнительные параметры в виде "a=1&b=2"

    возвращает JSON:
      {"url": ..., "param": ..., "payload": ..., "status": ..., "reflected": bool,
       "context": ..., "verdict": ...}
    """
    url = target_url.rstrip("/")
    headers = {"User-Agent": "vega-agent"}

    result = {
        "url": url,
        "param": param,
        "payload": payload,
        "method": method,
        "reflected": False,
        "context": None,
        "status": None,
        "verdict": "requires_verification",
    }

    try:
        if method.upper() == "GET":
            params = {param: payload}
            if extra_params:
                for kv in extra_params.split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        params[k] = v
            res = requests.get(url, params=params, headers=headers, timeout=15)
        else:
            data = {param: payload}
            if extra_params:
                for kv in extra_params.split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        data[k] = v
            res = requests.post(url, data=data, headers=headers, timeout=15)
    except Exception as e:
        result["error"] = str(e)
        return json.dumps(result, ensure_ascii=False, indent=2)

    body = (res.text or "")
    result["status"] = res.status_code
    result["body_len"] = len(body)
    result["body_preview"] = body[:500]

    # ============ проверка отражения payload ============
    if payload in body:
        result["reflected"] = True

        # ============ контекст отражения ============
        idx = body.find(payload)
        context_start = max(0, idx - 100)
        context_end = min(len(body), idx + len(payload) + 100)
        context = body[context_start:context_end]
        result["context"] = context

        # ============ проверка, что payload не экранирован ============
        escaped = any(x in context for x in ("&lt;", "&gt;", "&quot;", "&#x3C;"))
        result["escaped"] = escaped

        if not escaped and ("<script" in payload.lower() or "onerror" in payload.lower()):
            result["verdict"] = (
                "ПОДОЗРЕНИЕ НА XSS: payload отражён без экранирования "
                "в контексте, где может исполниться"
            )
        elif not escaped:
            result["verdict"] = (
                "HTML INJECTION: payload отражён без экранирования, "
                "но не содержит исполняемого JS"
            )
        else:
            result["verdict"] = (
                "requires_verification: payload отражён, но экранирован. "
                "Проверьте контекст вручную."
            )
    else:
        result["verdict"] = "ОК: payload не отражён в ответе"

    return json.dumps(result, ensure_ascii=False, indent=2)