"""
FINAL UPDATED POLICY ENGINE
Supports:
- ALLOW / MASK / BLOCK
- Multilingual attacks
- Secret extraction
- Jailbreak detection
- Mixed-language attacks
- PII-aware masking
- Proper reason codes
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

import yaml

CONFIG_PATH = os.environ.get(
    "GATEWAY_CONFIG",
    os.path.join("config", "gateway_config.yaml")
)

_cfg = None


# =============================================================================
# CONFIG
# =============================================================================

def _load_config() -> Dict:

    global _cfg

    if _cfg is None:

        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                _cfg = yaml.safe_load(f)

        except Exception:

            _cfg = {
                "thresholds": {
                    "rule_block": 0.6,
                    "semantic_block": 0.75,
                    "final_risk_block": 0.65,
                    "final_risk_mask": 0.3,
                    "pii_weight": 0.15,
                    "secret_weight": 0.2,
                }
            }

    return _cfg


# =============================================================================
# ATTACK REASONS
# =============================================================================

ATTACK_REASON_CODES = {

    # multilingual injections
    "INJECTION",
    "INJECTION_UR",
    "INJECTION_KO",
    "INJECTION_AR",

    # attacks
    "JAILBREAK",
    "OBFUSCATED",

    # extraction
    "SECRET_EXTRACTION",
    "SYSTEM_EXTRACTION",
    "SENSITIVE_EXFIL",

    # semantic
    "SEMANTIC_INJECTION",
    "TFIDF_INJECTION",

    # scoring
    "HIGH_RULE_SCORE",

    # rag
    "RAG_ATTACK",
    "RAG_ATTACK_UR",
    "RAG_ATTACK_KO",
    "RAG_ATTACK_AR",
}


SECRET_REASON_CODES = {

    "SECRET_EXTRACTION",
    "SYSTEM_EXTRACTION",
    "SENSITIVE_EXFIL",

    "INJECTION",
    "INJECTION_UR",
    "INJECTION_KO",
    "INJECTION_AR",

    "JAILBREAK",

    "SEMANTIC_INJECTION",

    "RAG_ATTACK",
    "RAG_ATTACK_UR",
    "RAG_ATTACK_KO",
    "RAG_ATTACK_AR",
}


# =============================================================================
# HIGH VALUE ENTITIES
# =============================================================================

SECRET_ENTITIES = {
    "API_KEY",
    "CNIC",
    "STUDENT_ID",
}


# =============================================================================
# POLICY ENGINE
# =============================================================================

def compute_policy(

    rule_score: float,
    semantic_score: float,

    pii_result: Dict[str, Any],

    rule_reasons: List[str],
    semantic_reasons: List[str],

    language: str = "en",
    is_mixed: bool = False,

) -> Tuple[float, str, List[str]]:

    cfg = _load_config()["thresholds"]

    pii_weight = cfg.get("pii_weight", 0.15)
    secret_weight = cfg.get("secret_weight", 0.2)

    block_thr = cfg.get("final_risk_block", 0.65)
    mask_thr = cfg.get("final_risk_mask", 0.3)

    rule_block = cfg.get("rule_block", 0.6)
    sem_block = cfg.get("semantic_block", 0.75)

    # =========================================================================
    # COMBINE REASONS
    # =========================================================================

    all_reasons = list(set(rule_reasons + semantic_reasons))

    # =========================================================================
    # ATTACK SCORE
    # =========================================================================

    attack_score = max(rule_score, semantic_score)

    # =========================================================================
    # ATTACK INTENT
    # =========================================================================

    has_attack_intent = (

        attack_score >= rule_block

        or attack_score >= sem_block

        or bool(
            set(all_reasons) & ATTACK_REASON_CODES
        )
    )

    # =========================================================================
    # PII INFO
    # =========================================================================

    pii_entities = pii_result.get("entities", [])

    entity_types = {
        e["type"]
        for e in pii_entities
    }

    has_secret_entity = bool(
        entity_types & SECRET_ENTITIES
    )

    has_attack_reason = bool(
        set(all_reasons) & SECRET_REASON_CODES
    )

    # =========================================================================
    # RISK BOOSTING
    # =========================================================================

    if has_secret_entity and (
        attack_score > 0.3
        or has_attack_reason
    ):

        extra = secret_weight

        if "SECRET_EXFIL_RISK" not in all_reasons:
            all_reasons.append(
                "SECRET_EXFIL_RISK"
            )

    elif pii_entities and has_attack_intent:

        extra = pii_weight

        if "PII_PRESENT" not in all_reasons:
            all_reasons.append(
                "PII_PRESENT"
            )

    elif pii_entities:

        extra = 0.0

        if "PII_PRESENT" not in all_reasons:
            all_reasons.append(
                "PII_PRESENT"
            )

    else:
        extra = 0.0

    # =========================================================================
    # MIXED LANGUAGE ATTACK BOOST
    # =========================================================================

    if is_mixed and attack_score > 0.2:

        attack_score = min(
            1.0,
            attack_score + 0.1
        )

        if "MIXED_LANGUAGE_ATTACK" not in all_reasons:
            all_reasons.append(
                "MIXED_LANGUAGE_ATTACK"
            )

    # =========================================================================
    # FINAL RISK
    # =========================================================================

    final_risk = round(
        min(1.0, attack_score + extra),
        4,
    )

    # =========================================================================
    # DECISION ENGINE
    # =========================================================================

    # -------------------------
    # FORCE BLOCK
    # -------------------------

    if (
        rule_score >= rule_block
        or semantic_score >= sem_block
    ):

        decision = "BLOCK"

        if (
            rule_score >= rule_block
            and "HIGH_RULE_SCORE"
            not in all_reasons
        ):
            all_reasons.append(
                "HIGH_RULE_SCORE"
            )

    # -------------------------
    # EXPLICIT ATTACKS
    # -------------------------

    elif has_attack_intent:

        decision = "BLOCK"

    # -------------------------
    # HIGH FINAL RISK
    # -------------------------

    elif final_risk >= block_thr:

        decision = "BLOCK"

    # -------------------------
    # BENIGN PII
    # -------------------------

    elif pii_entities and not has_attack_intent:

        decision = "MASK"

    # -------------------------
    # BORDERLINE PII
    # -------------------------

    elif (
        final_risk >= mask_thr
        and pii_entities
    ):

        decision = "MASK"

    # -------------------------
    # SAFE
    # -------------------------

    else:

        decision = "ALLOW"

    # =========================================================================
    # CLEAN DUPLICATES
    # =========================================================================

    all_reasons = list(dict.fromkeys(all_reasons))

    return (
        final_risk,
        decision,
        all_reasons,
    )


# =============================================================================
# OUTPUT PREPARATION
# =============================================================================

def prepare_output(

    decision: str,
    pii_result: Dict,
    original_text: str,

):

    # -------------------------------------------------------------------------
    # SAFE
    # -------------------------------------------------------------------------

    if decision == "ALLOW":

        return original_text

    # -------------------------------------------------------------------------
    # MASK
    # -------------------------------------------------------------------------

    elif decision == "MASK":

        return pii_result.get(
            "safe_text",
            original_text,
        )

    # -------------------------------------------------------------------------
    # BLOCK
    # -------------------------------------------------------------------------

    else:

        return None
