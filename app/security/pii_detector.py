
import re


EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"
)

AADHAAR_PATTERN = re.compile(
    r"(?<!\d)\d{4}(?:[\s-]?\d{4}){2}(?!\d)"
)

CARD_PATTERN = re.compile(
    r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"
)


def luhn_valid(number: str) -> bool:
    """Check whether a card number passes the Luhn checksum."""

    digits = [int(char) for char in number if char.isdigit()]

    if not 13 <= len(digits) <= 19:
        return False

    total = 0

    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2

            if digit > 9:
                digit -= 9

        total += digit

    return total % 10 == 0


def valid_indian_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)

    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]

    return len(digits) == 10 and digits[0] in "6789"


def mask_value(value: str, category: str) -> str:
    digits = re.sub(r"\D", "", value)

    if category == "EMAIL":
        username, domain = value.split("@", 1)
        return f"{username[:1]}***@{domain}"

    if category == "INDIAN_PHONE":
        return f"******{digits[-4:]}"

    if category in ("AADHAAR_LIKE", "CARD_LIKE"):
        return f"********{digits[-4:]}"

    return "[REDACTED]"


def detect_and_redact(text: str) -> dict:
    """
    Detect and redact supported PII categories.

    The original input is intentionally not included in the result
    to reduce accidental exposure through logging.
    """

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    detections = {}
    redacted_text = text

    candidates = [
        ("EMAIL", EMAIL_PATTERN, lambda value: True),
        ("INDIAN_PHONE", PHONE_PATTERN, valid_indian_phone),
        ("AADHAAR_LIKE", AADHAAR_PATTERN, lambda value: True),
        ("CARD_LIKE", CARD_PATTERN, luhn_valid),
    ]

    for category, pattern, validator in candidates:
        matches = [
            match
            for match in pattern.finditer(redacted_text)
            if validator(match.group())
        ]

        if not matches:
            continue

        detections[category] = len(matches)

        for match in reversed(matches):
            replacement = mask_value(match.group(), category)

            redacted_text = (
                redacted_text[:match.start()]
                + replacement
                + redacted_text[match.end():]
            )

    return {
        "redacted_text": redacted_text,
        "detections": detections,
        "total_detections": sum(detections.values()),
    }
