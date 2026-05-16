"""Tests for Presidio PII detection."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.pii.presidio_custom import analyze_pii


def test_email_detection():
    result = analyze_pii("My email is test@example.com")
    types = [e["type"] for e in result["entities"]]
    assert "EMAIL_ADDRESS" in types, f"EMAIL not found in {types}"
    assert "<EMAIL>" in result["safe_text"], "Email not masked"
    print("PASS test_email_detection")


def test_cnic_detection():
    result = analyze_pii("My CNIC is 35202-1234567-1")
    types = [e["type"] for e in result["entities"]]
    assert "CNIC" in types, f"CNIC not found in {types}"
    assert "<CNIC>" in result["safe_text"]
    print("PASS test_cnic_detection")


def test_student_id_detection():
    result = analyze_pii("My student ID is FA21-BCS-123")
    types = [e["type"] for e in result["entities"]]
    assert "STUDENT_ID" in types, f"STUDENT_ID not found in {types}"
    print("PASS test_student_id_detection")


def test_api_key_detection():
    result = analyze_pii("API key: sk-abcdefghijklmnop1234567890")
    types = [e["type"] for e in result["entities"]]
    assert "API_KEY" in types, f"API_KEY not found in {types}"
    assert "<API_KEY>" in result["safe_text"]
    print("PASS test_api_key_detection")


def test_phone_detection():
    result = analyze_pii("Call me at +92-300-1234567")
    types = [e["type"] for e in result["entities"]]
    assert "PHONE_NUMBER" in types, f"PHONE not found in {types}"
    print("PASS test_phone_detection")


def test_no_pii():
    result = analyze_pii("Explain supervised learning with one example.")
    assert len(result["entities"]) == 0
    assert result["pii_risk"] == 0.0
    print("PASS test_no_pii")


def test_composite_name_email():
    result = analyze_pii("I am Fatima Malik, my email is fatima@test.com")
    assert len(result["composites"]) > 0 or len(result["entities"]) >= 2
    print("PASS test_composite_name_email")


if __name__ == "__main__":
    test_email_detection()
    test_cnic_detection()
    test_student_id_detection()
    test_api_key_detection()
    test_phone_detection()
    test_no_pii()
    test_composite_name_email()
    print("\nAll PII tests passed!")
