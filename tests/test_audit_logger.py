
import json
import pytest

from app.security.audit_logger import write_audit_log


def test_audit_event_is_created(tmp_path):
    log_file = tmp_path / "audit.jsonl"

    event = write_audit_log(
        action="ALLOW",
        risk_score=0,
        log_file=log_file,
    )

    assert event["action"] == "ALLOW"
    assert event["risk_score"] == 0
    assert "request_id" in event
    assert "timestamp" in event
    assert log_file.exists()


def test_audit_event_is_valid_json(tmp_path):
    log_file = tmp_path / "audit.jsonl"

    write_audit_log("WARN", 35, log_file=log_file)

    with log_file.open(encoding="utf-8") as file:
        event = json.loads(file.readline())

    assert event["action"] == "WARN"


def test_multiple_events_are_appended(tmp_path):
    log_file = tmp_path / "audit.jsonl"

    write_audit_log("ALLOW", 0, log_file=log_file)
    write_audit_log("BLOCK", 50, log_file=log_file)

    lines = log_file.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2


def test_detection_categories_are_recorded(tmp_path):
    event = write_audit_log(
        action="WARN",
        risk_score=35,
        pii_count=1,
        injection_categories=["JAILBREAK"],
        output_categories=["EMAIL"],
        log_file=tmp_path / "audit.jsonl",
    )

    assert event["pii_count"] == 1
    assert event["injection_categories"] == ["JAILBREAK"]
    assert event["output_categories"] == ["EMAIL"]


def test_invalid_action():
    with pytest.raises(ValueError):
        write_audit_log("UNKNOWN", 0)


def test_invalid_risk_score():
    with pytest.raises(ValueError):
        write_audit_log("ALLOW", 150)


def test_invalid_pii_count():
    with pytest.raises(ValueError):
        write_audit_log("ALLOW", 0, pii_count=-1)


def test_sensitive_category_text_is_not_recorded(tmp_path):
    event = write_audit_log(
        action="WARN",
        risk_score=25,
        injection_categories=["JAILBREAK", "password=MySecret123"],
        log_file=tmp_path / "audit.jsonl",
    )

    assert event["injection_categories"] == ["JAILBREAK"]
    assert "MySecret123" not in str(event)


def test_canary_leak_status_is_recorded(tmp_path):
    event = write_audit_log(
        action="BLOCK",
        risk_score=50,
        canary_leak_detected=True,
        log_file=tmp_path / "audit.jsonl",
    )

    assert event["canary_leak_detected"] is True


def test_request_ids_are_unique(tmp_path):
    log_file = tmp_path / "audit.jsonl"

    first = write_audit_log("ALLOW", 0, log_file=log_file)
    second = write_audit_log("ALLOW", 0, log_file=log_file)

    assert first["request_id"] != second["request_id"]
