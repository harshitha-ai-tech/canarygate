
import pytest

from app.security.policy_engine import evaluate_prompt


def test_normal_prompt_is_allowed():
    result = evaluate_prompt(
        {"total_detections": 0},
        {"action": "ALLOW", "risk_score": 0}
    )

    assert result["action"] == "ALLOW"
    assert result["risk_score"] == 0


def test_pii_prompt_gets_warning():
    result = evaluate_prompt(
        {"total_detections": 2},
        {"action": "ALLOW", "risk_score": 0}
    )

    assert result["action"] == "WARN"
    assert result["pii_detected"] is True
    assert result["pii_count"] == 2


def test_injection_warning():
    result = evaluate_prompt(
        {"total_detections": 0},
        {"action": "WARN", "risk_score": 35}
    )

    assert result["action"] == "WARN"
    assert result["risk_score"] == 35


def test_injection_block():
    result = evaluate_prompt(
        {"total_detections": 0},
        {"action": "BLOCK", "risk_score": 50}
    )

    assert result["action"] == "BLOCK"


def test_pii_and_injection_block():
    result = evaluate_prompt(
        {"total_detections": 1},
        {"action": "BLOCK", "risk_score": 50}
    )

    assert result["action"] == "BLOCK"
    assert result["pii_detected"] is True


def test_pii_does_not_increase_injection_score():
    result = evaluate_prompt(
        {"total_detections": 3},
        {"action": "ALLOW", "risk_score": 10}
    )

    assert result["risk_score"] == 10


def test_invalid_pii_result():
    with pytest.raises(TypeError):
        evaluate_prompt("invalid", {"action": "ALLOW", "risk_score": 0})


def test_invalid_injection_action():
    with pytest.raises(ValueError):
        evaluate_prompt(
            {"total_detections": 0},
            {"action": "UNKNOWN", "risk_score": 0}
        )
