from langchain.tools import tool
import requests

@tool
def check_cookie_flags(target_url: str) -> str:
    """
    Проверяет флаги cookies (HttpOnly, Secure, SameSite).

    target_url — URL приложения

    Возвращает таблицу cookies и их флагов.
    """
    try:
        res = requests.get(target_url, timeout=10, allow_redirects=True)
        cookies = res.cookies

        if not cookies:
            # пробуем ещё раз с Set-Cookie из заголовков
            set_cookie = res.headers.get("Set-Cookie") or res.headers.get("set-cookie")
            if not set_cookie:
                return "cookies не установлены"

        lines = [f"URL: {res.url}", ""]
        # requests.cookies
        for c in cookies:
            flags = []
            flags.append("HttpOnly" if c.has_nonstandard_attr("HttpOnly") or getattr(c, "rest", {}).get("HttpOnly") else "NO HttpOnly")
            flags.append("Secure" if c.secure else "NO Secure")
            samesite = getattr(c, "get_nonstandard_attr", lambda x: None)("SameSite") or "not set"
            flags.append(f"SameSite={samesite}")
            lines.append(f"{c.name}={c.value[:40]}... | {' | '.join(flags)}")

        # fallback по заголовку Set-Cookie
        if not cookies and "set-cookie" in {k.lower() for k in res.headers}:
            raw = res.headers.get("Set-Cookie") or res.headers.get("set-cookie")
            lines.append(f"Raw Set-Cookie: {raw[:300]}")

        return "\n".join(lines) if len(lines) > 2 else "cookies не найдены или не удалось разобрать"
    except Exception as e:
        return f"ошибка запроса: {e}"