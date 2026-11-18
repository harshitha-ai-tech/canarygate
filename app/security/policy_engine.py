
def evaluate_prompt(pii_result: dict, injection_result: dict) -> dict:
    """
    Combine PII and prompt-injection results into one policy decision.

    PII is treated as a privacy warning because it should be redacted.
    Prompt injection determines whether the request must be blocked.
    """

    if not isinstance(pii_result, dict):
        raise TypeError("pii_result must be a dictionary.")

    if not isinstance(injection_result, dict):
        raise TypeError("injection_result must be a dictionary.")

    pii_count = pii_result.get("total_detections", 0)
    injection_score = injection_result.get("risk_score", 0)
    injection_action = injection_result.get("action", "ALLOW")

    if not isinstance(pii_count, int) or isinstance(pii_count, bool) or pii_count < 0:
        raise ValueError("PII detection count must be a non-negative integer.")

    if (
        not isinstance(injection_score, int)
        or isinstance(injection_score, bool)
        or not 0 <= injection_score <= 100
    ):
        raise ValueError("Injection risk score must be between 0 and 100.")

    if injection_action not in ("ALLOW", "WARN", "BLOCK"):
        raise ValueError("Invalid injection action.")

    reasons = []

    if pii_count > 0:
        reasons.append(
            f"Detected {pii_count} PII item(s). Redact before sending to the AI model."
        )

    if injection_action == "BLOCK":
        reasons.append("Prompt injection risk is high. Request blocked.")

    elif injection_action == "WARN":
        reasons.append("Suspicious prompt patterns detected. Review required.")

    if injection_action == "BLOCK":
        final_action = "BLOCK"

    elif injection_action == "WARN" or pii_count > 0:
        final_action = "WARN"

    else:
        final_action = "ALLOW"
        reasons.append("No significant security risks detected.")

    return {
        "action": final_action,
        "risk_score": injection_score,
        "pii_detected": pii_count > 0,
        "pii_count": pii_count,
        "reasons": reasons,
    }
