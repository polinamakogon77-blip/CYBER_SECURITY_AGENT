from langchain.tools import tool
import json
import requests
from ._helpers import login_juice_shop, _finding, BASE_TIMEOUT


@tool
def test_negative_quantity(
    base_url: str,
    add_endpoint: str,
    update_endpoint: str,
    item_id_field: str = "id",
    product_id_field: str = "ProductId",
    basket_id_field: str = "BasketId",
    quantity_field: str = "quantity",
    product_id: str = "1",
    negative_value: int = -100,
    auth_email: str = "",
    auth_password: str = "",
):
    """
    проверяет бизнес-логику: принимает ли сервер отрицательное quantity.

    шаги:
      1) логин (если auth_email задан — по нему, иначе — Juice Shop)
      2) POST add_endpoint — добавить товар с quantity=1
      3) PUT update_endpoint/{item_id} — изменить quantity на negative_value
      4) если сервер вернул 200 и negative_value в ответе → confirmed

    работает на любом приложении с корзиной.

    base_url - адрес приложения
    add_endpoint - эндпоинт добавления, например "/api/BasketItems"
    update_endpoint - эндпоинт обновления, например "/api/BasketItems/{id}"
    item_id_field - имя поля ID в ответе add (по умолчанию "id")
    product_id_field - имя поля товара в теле add (по умолчанию "ProductId")
    basket_id_field - имя поля корзины в теле add (по умолчанию "BasketId")
    quantity_field - имя поля количества (по умолчанию "quantity")
    product_id - ID товара для добавления
    negative_value - отрицательное значение для проверки (по умолчанию -100)
    auth_email - email для логина (если пусто — Juice Shop)
    auth_password - пароль для логина
    """
    # ========== логин ==========
    if auth_email:
        token, login_data = login_juice_shop(base_url, email=auth_email, password=auth_password)
    else:
        token, login_data = login_juice_shop(base_url)
    if not token:
        return json.dumps({"error": login_data}, ensure_ascii=False)

    bid = login_data.get("authentication", {}).get("bid") or login_data.get("bid")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    base = base_url.rstrip("/")

    # ========== добавить товар ==========
    add_body = {
        product_id_field: product_id,
        quantity_field: 1,
    }
    if bid and basket_id_field:
        add_body[basket_id_field] = bid

    try:
        add = requests.post(
            f"{base}{add_endpoint}",
            headers=headers,
            json=add_body,
            timeout=BASE_TIMEOUT,
        )
        if add.status_code not in (200, 201):
            return json.dumps(
                {"error": f"add status {add.status_code}: {add.text[:300]}"},
                ensure_ascii=False,
            )
        add_json = add.json()
        # ищем ID в data.<field> или в корне
        item_id = (
            add_json.get("data", {}).get(item_id_field)
            if isinstance(add_json.get("data"), dict)
            else None
        ) or add_json.get(item_id_field)
    except Exception as exc:
        return json.dumps({"error": f"add: {exc}"}, ensure_ascii=False)

    if not item_id:
        return json.dumps(
            {"error": f"no {item_id_field} in response: {add.text[:300]}"},
            ensure_ascii=False,
        )

    # ========== изменить quantity на negative_value ==========
    update_path = update_endpoint.replace("{id}", str(item_id))
    try:
        upd = requests.put(
            f"{base}{update_path}",
            headers=headers,
            json={quantity_field: negative_value},
            timeout=BASE_TIMEOUT,
        )
        upd_body = upd.text[:500]
    except Exception as exc:
        return json.dumps({"error": f"update: {exc}"}, ensure_ascii=False)

    # ========== вердикт ==========
    if upd.status_code == 200 and str(negative_value) in upd_body:
        f = _finding(
            title="Отрицательное количество в корзине",
            severity="medium",
            endpoint=f"{base}{update_path}",
            evidence=upd_body,
            description=f"Сервер принимает {quantity_field}={negative_value}, что делает сумму заказа отрицательной.",
            recommendation=f"Валидировать {quantity_field} > 0 на сервере.",
            tool="test_negative_quantity",
        )
    else:
        f = _finding(
            title="Negative quantity (не подтверждено)",
            severity="info",
            endpoint=f"{base}{update_path}",
            evidence=f"status={upd.status_code}, body={upd_body[:300]}",
            status="requires_verification",
            tool="test_negative_quantity",
        )
    return json.dumps({"findings": [f]}, ensure_ascii=False, indent=2)