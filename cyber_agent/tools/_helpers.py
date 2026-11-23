
"""Общие вспомогательные функции для инструментов безопасности."""

import requests


BASE_TIMEOUT = 15

# Учебные данные OWASP Juice Shop
ADMIN_EMAIL = "admin@juice-sh.op"
ADMIN_PASSWORD = "admin123"


def _finding(
    title: str,
    severity: str,
    endpoint: str,
    evidence: str,
    description: str = "",
    recommendation: str = "",
    status: str = "confirmed",
    tool: str = "",
) -> dict:
    """Формирует находку в общем формате Finding."""

    return {
        "title": title,
        "description": description or title,
        "severity": severity,
        "status": status,
        "endpoint": endpoint,
        "evidence": str(evidence)[:500],
        "recommendation": recommendation,
        "metadata": {
            "tool": tool,
        },
    }


def login_juice_shop(
    base: str,
    email: str = ADMIN_EMAIL,
    password: str = ADMIN_PASSWORD,
) -> tuple[str | None, dict]:
    """Авторизуется в учебном Juice Shop и возвращает токен и JSON-ответ."""

    try:
        response = requests.post(
            f"{base.rstrip('/')}/rest/user/login",
            json={
                "email": email,
                "password": password,
            },
            timeout=BASE_TIMEOUT,
        )

        if response.status_code != 200:
            return None, {
                "error": f"login status {response.status_code}",
            }

        data = response.json()

        token = data.get("authentication", {}).get("token")

        if not token:
            return None, {
                "error": "Токен отсутствует в ответе авторизации",
            }

        return token, data

    except requests.RequestException as exc:
        return None, {
            "error": f"Ошибка HTTP-запроса: {exc}",
        }

    except ValueError:
        return None, {
            "error": "Сервер вернул некорректный JSON",
        }
