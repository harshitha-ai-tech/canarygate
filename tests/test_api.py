
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "Canary Gate"


def test_chat_endpoint_success(monkeypatch):
    def fake_process_prompt(prompt):
        return {
            "action": "ALLOW",
            "risk_score": 0,
            "response": "Artificial intelligence is useful.",
            "reasons": [],
            "output_detections": {},
            "canary_leak_detected": False,
        }

    monkeypatch.setattr(
        "app.main.process_prompt",
        fake_process_prompt,
    )

    response = client.post(
        "/chat",
        json={"prompt": "Explain AI."},
    )

    assert response.status_code == 200
    assert response.json()["action"] == "ALLOW"
    assert response.json()["response"] == (
        "Artificial intelligence is useful."
    )


def test_chat_rejects_empty_prompt():
    response = client.post(
        "/chat",
        json={"prompt": "   "},
    )

    assert response.status_code == 400


def test_chat_rejects_missing_prompt():
    response = client.post(
        "/chat",
        json={},
    )

    assert response.status_code == 422


def test_chat_handles_gemini_failure(monkeypatch):
    def fake_process_prompt(prompt):
        raise RuntimeError("Internal API details")

    monkeypatch.setattr(
        "app.main.process_prompt",
        fake_process_prompt,
    )

    response = client.post(
        "/chat",
        json={"prompt": "Hello"},
    )

    assert response.status_code == 502
    assert "Internal API details" not in response.text


def test_chat_handles_invalid_prompt(monkeypatch):
    def fake_process_prompt(prompt):
        raise ValueError("Internal validation details")

    monkeypatch.setattr(
        "app.main.process_prompt",
        fake_process_prompt,
    )

    response = client.post(
        "/chat",
        json={"prompt": "Hello"},
    )

    assert response.status_code == 400
    assert "Internal validation details" not in response.text
