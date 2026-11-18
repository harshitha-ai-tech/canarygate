
import secrets


def generate_canary_token() -> str:
    """
    Generate a unique, unpredictable canary token.

    Use a separate token for each request.
    """

    return f"CANARY-{secrets.token_urlsafe(24)}"


def detect_canary_leak(text: str, token: str) -> dict:
    """
    Detect and redact a canary token if it appears in AI output.

    The original token is never included in the result.
    """

    if not isinstance(text, str):
        raise TypeError("Output must be a string.")

    if not isinstance(token, str):
        raise TypeError("Canary token must be a string.")

    if not token.strip():
        raise ValueError("Canary token cannot be empty.")

    leak_count = text.count(token)

    sanitized_text = text.replace(
        token,
        "[CANARY_TOKEN_REDACTED]"
    )

    return {
        "sanitized_text": sanitized_text,
        "leak_detected": leak_count > 0,
        "leak_count": leak_count,
    }
