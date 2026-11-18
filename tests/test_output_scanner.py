
import pytest

from app.security.output_scanner import scan_output


def test_normal_output():
    result = scan_output("Artificial intelligence helps solve problems.")

    assert result["total_detections"] == 0
    assert result["has_sensitive_content"] is False


def test_email_redaction():
    result = scan_output("Contact: test@gmail.com")

    assert result["detections"]["EMAIL"] == 1
    assert "test@gmail.com" not in result["sanitized_text"]


def test_phone_redaction():
    result = scan_output("Phone: 9876543210")

    assert result["detections"]["INDIAN_PHONE"] == 1
    assert "9876543210" not in result["sanitized_text"]


def test_google_api_key_detection():
    key = "AIza" + "A" * 30
    result = scan_output(f"API key: {key}")

    assert result["detections"]["GOOGLE_API_KEY"] == 1
    assert key not in result["sanitized_text"]


def test_password_assignment_detection():
    result = scan_output("password=MySecretPassword123")

    assert result["detections"]["CREDENTIAL_ASSIGNMENT"] == 1
    assert "MySecretPassword123" not in result["sanitized_text"]


def test_private_key_detection():
    private_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "sample-private-key-content\n"
        "-----END PRIVATE KEY-----"
    )

    result = scan_output(private_key)

    assert result["detections"]["PRIVATE_KEY"] == 1
    assert "sample-private-key-content" not in result["sanitized_text"]


def test_internal_instruction_marker():
    result = scan_output(
        "System prompt: follow internal rules."
    )

    assert result["detections"]["INTERNAL_INSTRUCTION_MARKER"] == 1
    assert "System prompt:" not in result["sanitized_text"]


def test_multiple_sensitive_items():
    result = scan_output(
        "Email test@gmail.com and password=MySecretPassword123"
    )

    assert result["total_detections"] == 2
    assert result["has_sensitive_content"] is True


def test_original_output_not_returned():
    secret = "password=MySecretPassword123"
    result = scan_output(secret)

    assert "original_text" not in result
    assert secret not in result["sanitized_text"]


def test_invalid_input():
    with pytest.raises(TypeError):
        scan_output(12345)
