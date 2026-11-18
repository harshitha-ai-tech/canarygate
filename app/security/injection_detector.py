
import re
import unicodedata


# Risk thresholds
WARN_THRESHOLD = 25
BLOCK_THRESHOLD = 50


# Each rule has a category, pattern, score and explanation.
INJECTION_RULES = [
    (
        "INSTRUCTION_OVERRIDE",
        r"\b(ignore|disregard|forget|override)\b.{0,60}\b(previous|prior|above|all|earlier)\b.{0,40}\b(instructions?|rules?|prompts?)\b",
        50,
        "Attempt to override existing instructions."
    ),
    (
        "SYSTEM_PROMPT_EXTRACTION",
        r"\b(reveal|show|print|display|expose|repeat|extract)\b.{0,60}\b(system prompt|hidden prompt|internal instructions?)\b",
        50,
        "Attempt to expose hidden system instructions."
    ),
    (
        "JAILBREAK",
        r"\b(unrestricted mode|developer mode|jailbreak|without any restrictions|bypass your restrictions)\b",
        35,
        "Possible attempt to bypass AI restrictions."
    ),
    (
        "ROLE_MANIPULATION",
        r"\b(pretend|act|behave)\b.{0,50}\b(as|like)\b.{0,30}\b(unrestricted|unfiltered|evil|different ai)\b",
        30,
        "Attempt to manipulate the AI's role."
    ),
    (
        "DEVELOPER_OVERRIDE",
        r"\b(ignore|override|bypass|disregard)\b.{0,40}\b(developer|system|safety)\b.{0,30}\b(instructions?|rules?|policies)\b",
        45,
        "Attempt to bypass developer or safety instructions."
    ),
    (
        "DATA_EXFILTRATION",
        r"\b(send|reveal|expose|leak|output|print)\b.{0,50}\b(api keys?|passwords?|credentials?|secret keys?|private data)\b",
        35,
        "Possible attempt to extract sensitive information."
    ),
]


def normalize_text(text: str) -> str:
    """Normalize text before checking security patterns."""

    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.lower()
    normalized = re.sub(r"\s+", " ", normalized)

    return normalized.strip()


def detect_prompt_injection(text: str) -> dict:
    """
    Detect common prompt injection patterns using lightweight rules.

    This is a heuristic detector, not a guarantee against all attacks.
    """

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    normalized = normalize_text(text)

    detections = []
    category_scores = {}

    for category, pattern, score, reason in INJECTION_RULES:

        if re.search(pattern, normalized):
            # Avoid repeatedly scoring the same category.
            if category not in category_scores:
                category_scores[category] = score

                detections.append({
                    "category": category,
                    "score": score,
                    "reason": reason
                })

    risk_score = min(sum(category_scores.values()), 100)

    if risk_score >= BLOCK_THRESHOLD:
        action = "BLOCK"
    elif risk_score >= WARN_THRESHOLD:
        action = "WARN"
    else:
        action = "ALLOW"

    return {
        "action": action,
        "risk_score": risk_score,
        "detections": detections,
        "total_detections": len(detections)
    }
