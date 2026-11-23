from langchain.tools import tool
import json
import requests
from ._helpers import _finding, BASE_TIMEOUT


@tool
def test_security_txt(base_url: str):
    """
    проверяет наличие security.txt по стандартным путям.

    1) сначала проверяет стандартный путь /.well-known/security.txt 
    2) если его нет (404) — проверяет /security.txt
    3) если найден — проверяет, что это текст с полями Contact/Expires

    возвращает Finding (confirmed, если файл найден и содержит обязательные поля).
    """
    base = base_url.rstrip("/")

    well_known_path = "/.well-known/security.txt"
    legacy_path = "/security.txt"

    checked = []
    found_url = None
    found_body = None
    found_status = None

    # ========== стандартный путь ==========
    url = f"{base}{well_known_path}"
    try:
        r = requests.get(url, timeout=BASE_TIMEOUT, allow_redirects=True)
        checked.append({
            "path": well_known_path,
            "status": r.status_code,
            "len": len(r.text or ""),
            "content_type": r.headers.get("Content-Type", ""),
        })
        if r.status_code == 200 and r.text:
            found_url = url
            found_body = r.text
            found_status = r.status_code
    except Exception as exc:
        checked.append({"path": well_known_path, "error": str(exc)})

    # ========== устаревший путь ==========
    if not found_url:
        url = f"{base}{legacy_path}"
        try:
            r = requests.get(url, timeout=BASE_TIMEOUT, allow_redirects=True)
            checked.append({
                "path": legacy_path,
                "status": r.status_code,
                "len": len(r.text or ""),
                "content_type": r.headers.get("Content-Type", ""),
            })
            if r.status_code == 200 and r.text:
                found_url = url
                found_body = r.text
                found_status = r.status_code
        except Exception as exc:
            checked.append({"path": legacy_path, "error": str(exc)})

    # ========== ничего не нашли ==========
    if not found_url:
        f = _finding(
            title="security.txt не найден",
            severity="info",
            endpoint=f"{base}{well_known_path}",
            evidence=json.dumps(checked, ensure_ascii=False),
            status="requires_verification",
            description="Файл security.txt не найден ни по стандартному, ни по устаревшему пути.",
            recommendation="Опубликовать security.txt по пути /.well-known/security.txt (RFC 9116).",
            tool="test_security_txt",
        )
        return json.dumps({"findings": [f]}, ensure_ascii=False, indent=2)

    # ========== проверка содержимого ==========
    body_lower = found_body.lower()
    has_contact = "contact:" in body_lower
    has_expires = "expires:" in body_lower
    is_plain = "text/plain" in (checked[-1].get("content_type", "") or "").lower()

    # ========== вердикт ==========
    if has_contact and has_expires:
        f = _finding(
            title="security.txt опубликован",
            severity="low",
            endpoint=found_url,
            evidence=found_body[:500],
            status="confirmed",
            description=(
                f"Файл security.txt найден по пути {found_url} "
                f"и содержит обязательные поля Contact и Expires."
            ),
            recommendation="Поддерживать contact/expires в актуальном состоянии.",
            tool="test_security_txt",
        )
    else:
        missing = []
        if not has_contact:
            missing.append("Contact")
        if not has_expires:
            missing.append("Expires")
        f = _finding(
            title="security.txt найден, но неполный",
            severity="info",
            endpoint=found_url,
            evidence=f"missing={missing}; body={found_body[:300]}",
            status="requires_verification",
            description=f"Файл найден, но отсутствуют обязательные поля: {', '.join(missing)}.",
            recommendation="Добавить обязательные поля Contact и Expires (RFC 9116).",
            tool="test_security_txt",
        )

    return json.dumps({"findings": [f]}, ensure_ascii=False, indent=2)