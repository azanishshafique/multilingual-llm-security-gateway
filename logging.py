
from __future__ import annotations

import json
import os
import logging
from datetime import datetime, timezone
from typing import Any, Dict

LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "results/audit_log.jsonl")

# Standard Python logger for console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("gateway")


def write_audit(record: Dict[str, Any]) -> None:
    """Append a JSON audit record to the audit log file."""
    os.makedirs(os.path.dirname(LOG_PATH) if os.path.dirname(LOG_PATH) else ".", exist_ok=True)
    record["timestamp"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"Audit log write failed: {e}")


def get_logger():
    return logger
