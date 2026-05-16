"""
LLM Security Gateway - Main FastAPI Application
Endpoints: POST /analyze, POST /batch_analyze, GET /health, GET /config
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Internal modules
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.detectors.rule_detector import rule_detect
from app.detectors.semantic_detector import semantic_detect, warm_up
from app.pii.presidio_custom import analyze_pii
from app.policy.policy_engine import compute_policy, prepare_output
from app.utils.language import detect_language, is_mixed_language
from app.utils.logging import write_audit, get_logger

logger = get_logger()

app = FastAPI(
    title="LLM Security Gateway",
    description="Robust Multilingual Security Gateway for LLM Applications (CSC 262)",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    input_id: Optional[str] = None
    text: str
    mode: Optional[str] = "hybrid"  # "rule_only" | "hybrid"


class BatchAnalyzeRequest(BaseModel):
    items: List[AnalyzeRequest]


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def run_pipeline(text: str, input_id: str, mode: str = "hybrid") -> Dict[str, Any]:
    t0 = time.perf_counter()

    # 1. Language detection
    language = detect_language(text)
    mixed = is_mixed_language(text)

    # 2. Rule-based detection
    rule_score, rule_reasons = rule_detect(text)

    # 3. Semantic detection (skipped in rule_only mode)
    if mode == "hybrid":
        semantic_score, semantic_reasons = semantic_detect(text)
    else:
        semantic_score, semantic_reasons = 0.0, []

    # 4. PII detection
    pii_result = analyze_pii(text)

    # 5. Policy engine
    final_risk, decision, all_reasons = compute_policy(
        rule_score=rule_score,
        semantic_score=semantic_score,
        pii_result=pii_result,
        rule_reasons=rule_reasons,
        semantic_reasons=semantic_reasons,
        language=language,
        is_mixed=mixed,
    )

    # 6. Prepare output
    safe_text = prepare_output(decision, pii_result, text)

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    response = {
        "input_id": input_id,
        "language": language,
        "mixed_language": mixed,
        "rule_score": rule_score,
        "semantic_score": semantic_score,
        "pii_entities": pii_result["entities"],
        "pii_risk": pii_result["pii_risk"],
        "composite_entities": pii_result.get("composites", []),
        "final_risk": final_risk,
        "decision": decision,
        "safe_text": safe_text,
        "reason_codes": all_reasons,
        "latency_ms": latency_ms,
        "mode": mode,
    }

    # 7. Audit log
    write_audit(response)
    logger.info(f"[{input_id}] lang={language} rule={rule_score} sem={semantic_score} "
                f"risk={final_risk} decision={decision} latency={latency_ms}ms")

    return response


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    warm_up()
    logger.info("Gateway started and models loaded.")


@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.get("/config")
def get_config():
    import yaml
    config_path = os.environ.get("CONFIG_PATH", "config/gateway_config.yaml")
    try:
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
        return cfg
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="text field is required and cannot be empty.")

    input_id = request.input_id or f"req_{uuid.uuid4().hex[:8]}"
    mode = request.mode or "hybrid"

    return run_pipeline(text=request.text, input_id=input_id, mode=mode)


@app.post("/batch_analyze")
def batch_analyze(request: BatchAnalyzeRequest):
    results = []
    for item in request.items:
        input_id = item.input_id or f"req_{uuid.uuid4().hex[:8]}"
        result = run_pipeline(text=item.text, input_id=input_id, mode=item.mode or "hybrid")
        results.append(result)
    return {"results": results, "count": len(results)}


@app.post("/rule_only")
def rule_only(request: AnalyzeRequest):
    """Rule-only mode for baseline comparison."""
    input_id = request.input_id or f"req_{uuid.uuid4().hex[:8]}"
    return run_pipeline(text=request.text, input_id=input_id, mode="rule_only")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
