"""Tests for policy engine."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.policy.policy_engine import compute_policy, prepare_output


def test_allow():
    final_risk, decision, reasons = compute_policy(
        rule_score=0.0, semantic_score=0.0,
        pii_result={"entities": [], "pii_risk": 0.0, "composites": []},
        rule_reasons=[], semantic_reasons=[], language="en"
    )
    assert decision == "ALLOW", f"Expected ALLOW got {decision}"
    print("PASS test_allow")


def test_block_rule():
    final_risk, decision, reasons = compute_policy(
        rule_score=0.7, semantic_score=0.0,
        pii_result={"entities": [], "pii_risk": 0.0, "composites": []},
        rule_reasons=["INJECTION"], semantic_reasons=[], language="en"
    )
    assert decision == "BLOCK", f"Expected BLOCK got {decision}"
    print("PASS test_block_rule")


def test_block_semantic():
    final_risk, decision, reasons = compute_policy(
        rule_score=0.0, semantic_score=0.8,
        pii_result={"entities": [], "pii_risk": 0.0, "composites": []},
        rule_reasons=[], semantic_reasons=["SEMANTIC_INJECTION"], language="en"
    )
    assert decision == "BLOCK", f"Expected BLOCK got {decision}"
    print("PASS test_block_semantic")


def test_mask_pii():
    final_risk, decision, reasons = compute_policy(
        rule_score=0.0, semantic_score=0.1,
        pii_result={"entities": [{"type": "EMAIL_ADDRESS", "text": "a@b.com", "score": 0.9, "start": 0, "end": 6}],
                    "pii_risk": 0.5, "composites": []},
        rule_reasons=[], semantic_reasons=[], language="en"
    )
    assert decision == "MASK", f"Expected MASK got {decision}"
    print("PASS test_mask_pii")


def test_prepare_output_block():
    out = prepare_output("BLOCK", {"safe_text": "masked"}, "original")
    assert out is None
    print("PASS test_prepare_output_block")


def test_prepare_output_mask():
    out = prepare_output("MASK", {"safe_text": "<EMAIL>"}, "original email@test.com")
    assert out == "<EMAIL>"
    print("PASS test_prepare_output_mask")


if __name__ == "__main__":
    test_allow()
    test_block_rule()
    test_block_semantic()
    test_mask_pii()
    test_prepare_output_block()
    test_prepare_output_mask()
    print("\nAll policy tests passed!")
