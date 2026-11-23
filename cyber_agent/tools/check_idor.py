# проверка на IDOR
from langchain.tools import tool
import requests
import json


DEFAULT_ADMIN_EMAIL = "admin@juice-sh.op"
DEFAULT_ADMIN_PASSWORD = "admin123"


def _login_juice_shop(base_url: str, email: str, password: str) -> tuple[str | None, int | None, str]:
    """Логинится в Juice Shop и возвращает (token, bid, error)."""
    login_url = f"{base_url.rstrip('/')}/rest/user/login"
    try:
        res = requests.post(
            login_url,
            json={"email": email, "password": password},
            timeout=15,
        )
    except Exception as e:
        return None, None, f"ошибка логина: {e}"

    if res.status_code != 200:
        return None, None, f"логин вернул {res.status_code}: {res.text[:200]}"

    try:
        data = res.json()
        auth = data.get("authentication", {})
        token = auth.get("token")
        bid = auth.get("bid")  
    except Exception as e:
        return None, None, f"не удалось распарсить ответ логина: {e}"

    if not token:
        return None, None, f"в ответе нет token: {data}"
    return token, bid, ""


@tool
def check_idor(url: str, endpoint: str, id_object: str, token: str = "", my_id: str = "",
    admin_email: str = DEFAULT_ADMIN_EMAIL, admin_password: str = DEFAULT_ADMIN_PASSWORD):
    """
    проверяет IDOR: может ли аутентифицированный пользователь получить
    доступ к объекту, который ему не принадлежит

    url - базовый адрес
    endpoint - точка входа
    id_object - ID чужого объекта
    token - Bearer-токен. Если пустой — логинимся как админ
    my_id - ID своего объекта. Если пустой — берём bid из ответа логина
    admin_email - email для логина (по умолчанию admin@juice-sh.op)
    admin_password - пароль для логина (по умолчанию admin123)

    возвращает JSON: {"target_url": ..., "verdict": ..., "checks": [...]}
    """
    base = url.rstrip("/")
    login_error = ""

    # ========== токен и my_id ==========
    if not token:
        token, bid_from_login, login_error = _login_juice_shop(
            base, admin_email, admin_password
        )
        if not token:
            return json.dumps({
                "error": login_error or "не удалось получить токен",
                "hint": "передайте token вручную или проверьте креды",
            }, ensure_ascii=False, indent=2)
        # если my_id не задан и endpoint — /rest/basket, берём bid из логина
        if not my_id and bid_from_login and endpoint.rstrip("/").endswith("/basket"):
            my_id = str(bid_from_login)

    headers = {"Authorization": f"Bearer {token}"}

    result = {
        "target_url": f"{base}{endpoint}/{id_object}",
        "id_object": id_object,
        "my_id": my_id or None,
        "checks": [],
        "verdict": "requires_verification",
        "login_error": login_error or None,
    }

    # ========== запрос к чужому объекту ==========
    foreign_url = f"{base}{endpoint}/{id_object}"
    try:
        res = requests.get(foreign_url, headers=headers, timeout=15)
        body = res.text or ""
        result["checks"].append({
            "target": "foreign",
            "url": foreign_url,
            "id": id_object,
            "status": res.status_code,
            "body_len": len(body),
            "body_preview": body[:300],
            "is_empty": len(body.strip()) == 0,
        })
    except Exception as e:
        result["error"] = f"ошибка запроса к {foreign_url}: {e}"
        return json.dumps(result, ensure_ascii=False, indent=2)

    # ========== сравнение со своим объектом (если my_id задан) ==========
    if my_id and str(my_id) != str(id_object):
        own_url = f"{base}{endpoint}/{my_id}"
        try:
            own = requests.get(own_url, headers=headers, timeout=15)
            own_body = own.text or ""
            result["checks"].append({
                "target": "own",
                "url": own_url,
                "id": my_id,
                "status": own.status_code,
                "body_len": len(own_body),
                "body_preview": own_body[:300],
                "is_empty": len(own_body.strip()) == 0,
            })

            foreign_ok = res.status_code == 200 and len(body.strip()) > 0
            own_ok = own.status_code == 200 and len(own_body.strip()) > 0

            if foreign_ok and own_ok:
                # пробуем сравнить владельца в JSON
                same_owner = _same_owner(body, own_body)
                if same_owner is False:
                    result["verdict"] = (
                        "IDOR ПОДТВЕРЖДЁН: доступ к чужому объекту, "
                        "UserId в ответе не совпадает с вашим"
                    )
                elif same_owner is True:
                    result["verdict"] = "ОК: доступ к объекту своего пользователя"
                elif body.strip() != own_body.strip():
                    result["verdict"] = (
                        "ПОДОЗРЕНИЕ НА IDOR: доступ к чужому объекту, "
                        "тело отличается от вашего"
                    )
                else:
                    result["verdict"] = "ОК: данные совпадают с вашим объектом"
            elif foreign_ok and not own_ok:
                result["verdict"] = (
                    "requires_verification: доступ к чужому 200, "
                    "но ваш объект недоступен"
                )
            else:
                result["verdict"] = f"ОК: статус {res.status_code}"
        except Exception as e:
            result["verdict"] = f"ошибка сравнения с my_id: {e}"
    else:
        # без my_id — только предварительная проверка
        if res.status_code == 200 and len(body.strip()) > 0:
            result["verdict"] = (
                "requires_verification: HTTP 200, но нет сравнения с "
                "вашим объектом. Передайте my_id для подтверждения."
            )
        elif res.status_code == 200:
            result["verdict"] = "ОК: HTTP 200, но тело пустое"
        elif res.status_code in (401, 403):
            result["verdict"] = "ОК: доступ запрещён (401/403)"
        else:
            result["verdict"] = f"ОК: статус {res.status_code}"

    return json.dumps(result, ensure_ascii=False, indent=2)


def _same_owner(foreign_body: str, own_body: str):
    """
    True — один владелец, False — разный, None — не удалось определить
    """
    try:
        f = json.loads(foreign_body)
        o = json.loads(own_body)
    except Exception:
        return None

    def owner_id(obj):
        if isinstance(obj, dict):
            for k in ("UserId", "userId", "user_id", "ownerId"):
                if k in obj:
                    return str(obj[k])
        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            return owner_id(obj[0])
        return None

    fid = owner_id(f)
    oid = owner_id(o)
    if fid is None or oid is None:
        return None
    return fid == oid