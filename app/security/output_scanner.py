
import re

from app.security.pii_detector import detect_and_redact


SECRET_PATTERNS = [
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    ),
    (
        "CREDENTIAL_ASSIGNMENT",
        re.compile(
            r"""(?i)\b(api[_ -]?key|secret[_ -]?key|access[_ -]?token|password)\b\s*[:=]\s*["']?[A-Za-z0-9._/\-+=]{8,}"""
        ),
    ),
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    (
        "INTERNAL_INSTRUCTION_MARKER",
        re.compile(
            r"(?i)\b(?:system prompt|internal instructions|developer instructions)\s*:"
        ),
    ),
]


def scan_output(text: str) -> dict:
    """
    Scan AI-generated output for PII, credentials and instruction markers.

    Detected content is redacted before the sanitized text is returned.
    The original unredacted output is not included in the result.
    """

    if not isinstance(text, str):
        raise TypeError("Output must be a string.")

    # First, detect and redact common PII.
    pii_result = detect_and_redact(text)
    sanitized_text = pii_result["redacted_text"]

    detections = dict(pii_result["detections"])

    # Then scan the remaining text for secrets and instruction markers.
    for category, pattern in SECRET_PATTERNS:
        matches = list(pattern.finditer(sanitized_text))

        if not matches:
            continue

        detections[category] = len(matches)

        # Replace from right to left so earlier match positions stay valid.
        for match in reversed(matches):
            sanitized_text = (
                sanitized_text[:match.start()]
                + f"[{category}_REDACTED]"
                + sanitized_text[match.end():]
            )

    return {
        "sanitized_text": sanitized_text,
        "detections": detections,
        "total_detections": sum(detections.values()),
        "has_sensitive_content": bool(detections),
    }
