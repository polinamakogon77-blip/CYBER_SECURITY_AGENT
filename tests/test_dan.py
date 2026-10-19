import requests

def test_dan_health():
    response = requests.get(
        "http://127.0.0.1:5001/health",
        timeout=10
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dan_chat():
    response = requests.post(
        "http://127.0.0.1:5001/api/chat",
        json={"prompt": "Привет!"},
        timeout=60
    )
    assert response.status_code == 200
    assert "response" in response.json()

# запуск при работающем стенде python -m pytest tests/test_dan.py -v
