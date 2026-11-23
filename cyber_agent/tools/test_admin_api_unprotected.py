from langchain.tools import tool
import json
import requests
from ._helpers import login_juice_shop, _finding, BASE_TIMEOUT


@tool
def test_admin_api_unprotected(base_url: str):
    """
    проверяет, доступен ли /api/Users с токеном обычного пользователя
    """

    # логинимся как обычный пользователь 
    token, login_data = login_juice_shop(
        base_url, email="jim@juice-sh.op", password="ncc-1701"
    )
    if not token:
        # используем админский токен, но проверяем отсутствие role-check
        token, login_data = login_juice_shop(base_url)
        if not token:
            return json.dumps({"error": login_data}, ensure_ascii=False)

    try:
        r = requests.get(
            f"{base_url.rstrip('/')}/api/Users",
            headers={"Authorization": f"Bearer {token}"},
            timeout=BASE_TIMEOUT,
        )
        body = r.text[:1000]
    except Exception as exc:
        return json.dumps({"error": str(exc)})

    if r.status_code == 200 and '"email"' in body:
        f = _finding(
            title="Unprotected Admin API (/api/Users)",
            severity="high",
            endpoint=f"{base_url}/api/Users",
            evidence=body,
            description="Эндпоинт возвращает список пользователей без проверки роли admin.",
            recommendation="Добавить проверку role === 'admin' в middleware.",
            tool="test_admin_api_unprotected",
        )
    else:
        f = _finding(
            title="Admin API (не подтверждено)",
            severity="info",
            endpoint=f"{base_url}/api/Users",
            evidence=f"status={r.status_code}, body={body[:300]}",
            status="requires_verification",
            tool="test_admin_api_unprotected",
        )
    return json.dumps({"findings": [f]}, ensure_ascii=False, indent=2)