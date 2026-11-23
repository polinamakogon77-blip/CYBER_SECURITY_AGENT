from langchain.tools import tool
import requests

IMPORTANT_HEADERS = {
    "Content-Security-Policy": "CSP",
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
    "X-XSS-Protection": "X-XSS-Protection (legacy)",
}

@tool
def check_security_headers(target_url: str) -> str:
    """
    Проверяет наличие важных security-заголовков.

    target_url — URL приложения

    Возвращает таблицу заголовков и их статусов.
    """
    try:
        res = requests.get(target_url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in res.headers.items()}

        lines = [f"URL: {res.url}", f"status={res.status_code}", ""]
        for header, name in IMPORTANT_HEADERS.items():
            key = header.lower()
            if key in headers:
                lines.append(f"[OK] {name}: {headers[key][:120]}")
            else:
                lines.append(f"[MISSING] {name}")

        return "\n".join(lines)
    except Exception as e:
        return f"ошибка запроса: {e}"