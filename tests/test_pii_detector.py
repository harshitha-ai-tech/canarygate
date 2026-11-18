
import pytest

from app.security.pii_detector import (
    detect_and_redact,
    luhn_valid,
)


def test_email_detection():
    result = detect_and_redact("Email: test@gmail.com")
    assert result["detections"]["EMAIL"] == 1
    assert "test@gmail.com" not in result["redacted_text"]


def test_indian_phone_detection():
    result = detect_and_redact("Phone: 9876543210")
    assert result["detections"]["INDIAN_PHONE"] == 1


def test_phone_with_country_code():
    result = detect_and_redact("Phone: +91 98765 43210")
    assert result["detections"]["INDIAN_PHONE"] == 1


def test_phone_with_hyphens():
    result = detect_and_redact("Phone: 98765-43210")
    assert result["detections"]["INDIAN_PHONE"] == 1


def test_invalid_phone_not_detected():
    result = detect_and_redact("Phone: 1234567890")
    assert result["total_detections"] == 0


def test_aadhaar_like_detection():
    result = detect_and_redact("Number: 1234 5678 9012")
    assert result["detections"]["AADHAAR_LIKE"] == 1


def test_card_luhn_validation():
    assert luhn_valid("4532015112830366")
    assert not luhn_valid("4532015112830367")


def test_valid_card_detection():
    result = detect_and_redact("Card: 4532015112830366")
    assert result["detections"]["CARD_LIKE"] == 1


def test_invalid_card_not_detected():
    result = detect_and_redact("Card: 4532015112830367")
    assert "CARD_LIKE" not in result["detections"]


def test_normal_text():
    result = detect_and_redact("Hello, how are you?")
    assert result["total_detections"] == 0


def test_multiple_pii():
    result = detect_and_redact(
        "Email test@gmail.com and phone 9876543210"
    )
    assert result["total_detections"] == 2


def test_non_string_input():
    with pytest.raises(TypeError):
        detect_and_redact(12345)
