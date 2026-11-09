from langchain.tools import tool
import requests
import json

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("user", "user"),
    ("test", "test"),
]

@tool
def test_default_credentials(
    login_url: str,
    credentials_list: str = "",
) -> str:
    """
    Пробует типовые пары логин/пароль.

    login_url — URL формы логина (POST)
    credentials_list — JSON-строка списка пар [["user","pass"], ...] 
                       (если пусто — использует встроенный список)

    Возвращает список сработавших пар.
    """
    if credentials_list:
        try:
            pairs = json.loads(credentials_list)
        except json.JSONDecodeError:
            return "ошибка: credentials_list должен быть валидным JSON"
    else:
        pairs = DEFAULT_CREDS

    success = []
    errors = []

    for username, password in pairs:
        try:
            res = requests.post(
                login_url,
                json={"username": username, "password": password},
                timeout=8,
                allow_redirects=False,
            )
            # эвристика успеха
            if res.status_code in (200, 302) and (
                "token" in res.text.lower()
                or "success" in res.text.lower()
                or "welcome" in res.text.lower()
                or res.status_code == 302
            ):
                success.append(f"{username}:{password} (status={res.status_code})")
        except Exception as e:
            errors.append(f"{username}:{password} → {e}")

    if not success:
        return "ни одна пара не сработала" + (f"\nошибки: {errors[:3]}" if errors else "")

    return "сработавшие пары:\n" + "\n".join(success)