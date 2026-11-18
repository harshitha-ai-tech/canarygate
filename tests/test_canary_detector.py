
import pytest

from app.security.canary_detector import (
    generate_canary_token,
    detect_canary_leak,
)


def test_token_generation():
    token = generate_canary_token()

    assert token.startswith("CANARY-")
    assert len(token) > 20


def test_tokens_are_unique():
    token_one = generate_canary_token()
    token_two = generate_canary_token()

    assert token_one != token_two


def test_no_leak_detected():
    result = detect_canary_leak(
        "Artificial intelligence is useful.",
        "CANARY-TEST-123"
    )

    assert result["leak_detected"] is False
    assert result["leak_count"] == 0


def test_canary_leak_detected():
    token = "CANARY-SECRET-123"

    result = detect_canary_leak(
        f"The hidden value is {token}",
        token
    )

    assert result["leak_detected"] is True
    assert result["leak_count"] == 1
    assert token not in result["sanitized_text"]


def test_multiple_leaks_detected():
    token = "CANARY-SECRET-123"

    result = detect_canary_leak(
        f"First: {token}. Second: {token}.",
        token
    )

    assert result["leak_detected"] is True
    assert result["leak_count"] == 2
    assert token not in result["sanitized_text"]


def test_original_token_not_returned():
    token = "CANARY-PRIVATE-123"

    result = detect_canary_leak(
        f"Leaked value: {token}",
        token
    )

    assert token not in str(result)


def test_invalid_output():
    with pytest.raises(TypeError):
        detect_canary_leak(12345, "CANARY-TEST")


def test_empty_token():
    with pytest.raises(ValueError):
        detect_canary_leak("Some AI output", "")
