"""Общие хелперы для инструментов поиска уязвимостей Juice Shop."""
import json
import requests

BASE_TIMEOUT = 15

ADMIN_EMAIL = "admin@juice-sh.op"
ADMIN_PASSWORD = "admin123"


def _finding(title: str, severity: str, endpoint: str, evidence: str,
             description: str = "", recommendation: str = "",
             status: str = "confirmed", tool: str = "") -> dict:
    """Собирает dict в формате Finding."""
    return {
        "title": title,
        "description": description or title,
        "severity": severity,
        "status": status,
        "endpoint": endpoint,
        "evidence": evidence[:500],
        "recommendation": recommendation,
        "metadata": {"tool": tool},
    }


def login_juice_shop(base: str, email: str = ADMIN_EMAIL,
                     password: str = ADMIN_PASSWORD) -> tuple[str | None, dict]:
    """Логинится и возвращает (token, full_response_json)."""
    try:
        r = requests.post(
            f"{base.rstrip('/')}/rest/user/login",
            json={"email": email, "password": password},
            timeout=BASE_TIMEOUT,
        )
        if r.status_code != 200:
            return None, {"error": f"login status {r.status_code}", "body": r.text[:300]}
        data = r.json()
        token = data.get("authentication", {}).get("token")
        return token, data
    except Exception as exc:
        return None, {"error": str(exc)}