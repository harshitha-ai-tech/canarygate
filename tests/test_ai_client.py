
import pytest

from app import ai_client


def test_empty_prompt():
    with pytest.raises(ValueError):
        ai_client.generate_ai_response("")


def test_non_string_prompt():
    with pytest.raises(TypeError):
        ai_client.generate_ai_response(123)


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        ai_client.generate_ai_response("Explain AI")


def test_successful_gemini_response(monkeypatch):
    class FakeResponse:
        text = "Artificial Intelligence enables machines to perform tasks."

    class FakeModels:
        def generate_content(self, model, contents):
            assert model == "gemini-2.5-flash"
            assert contents == "Explain AI"
            return FakeResponse()

    class FakeClient:
        def __init__(self, api_key):
            self.models = FakeModels()

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")
    monkeypatch.setattr(ai_client.genai, "Client", FakeClient)

    result = ai_client.generate_ai_response("Explain AI")

    assert result.startswith("Artificial Intelligence")


def test_empty_gemini_response(monkeypatch):
    class FakeResponse:
        text = None

    class FakeModels:
        def generate_content(self, model, contents):
            return FakeResponse()

    class FakeClient:
        def __init__(self, api_key):
            self.models = FakeModels()

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(ai_client.genai, "Client", FakeClient)

    with pytest.raises(RuntimeError, match="empty response"):
        ai_client.generate_ai_response("Explain AI")
