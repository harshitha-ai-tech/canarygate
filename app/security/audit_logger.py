
import json
import re
import uuid

from datetime import datetime, timezone
from pathlib import Path


DEFAULT_LOG_FILE = Path("logs/security_audit.jsonl")

CATEGORY_PATTERN = re.compile(r"^[A-Z0-9_]{1,50}$")


def _safe_categories(categories):
    """Keep only simple category identifiers, never arbitrary text."""

    if categories is None:
        return []

    if not isinstance(categories, list):
        raise TypeError("Categories must be provided as a list.")

    return [
        category
        for category in categories
        if isinstance(category, str)
        and CATEGORY_PATTERN.fullmatch(category)
    ]


def write_audit_log(
    action: str,
    risk_score: int,
    pii_count: int = 0,
    injection_categories: list = None,
    output_categories: list = None,
    canary_leak_detected: bool = False,
    log_file: Path = DEFAULT_LOG_FILE,
) -> dict:
    """
    Write a metadata-only security audit event.

    Never pass prompts, AI responses, PII values, API keys,
    or canary tokens to this function.
    """

    if action not in ("ALLOW", "WARN", "BLOCK"):
        raise ValueError("Invalid security action.")

    if (
        not isinstance(risk_score, int)
        or isinstance(risk_score, bool)
        or not 0 <= risk_score <= 100
    ):
        raise ValueError("Risk score must be between 0 and 100.")

    if (
        not isinstance(pii_count, int)
        or isinstance(pii_count, bool)
        or pii_count < 0
    ):
        raise ValueError("PII count must be a non-negative integer.")

    if not isinstance(canary_leak_detected, bool):
        raise TypeError("Canary leak status must be a boolean.")

    if not isinstance(log_file, (str, Path)):
        raise TypeError("Log file must be a string or Path.")

    event = {
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "risk_score": risk_score,
        "pii_count": pii_count,
        "injection_categories": _safe_categories(injection_categories),
        "output_categories": _safe_categories(output_categories),
        "canary_leak_detected": canary_leak_detected,
    }

    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return event
