"""
Microsoft Presidio customization:
- Custom recognizers: CNIC, STUDENT_ID, API_KEY, LOCAL_PHONE (PK)
- Context-aware score boosting
- Composite entity detection
- Confidence thresholding
- FIXED false masking for Korean/Arabic/Urdu safe text
"""

from __future__ import annotations

import re
from typing import List, Dict, Any, Optional

from presidio_analyzer import (
    AnalyzerEngine,
    RecognizerResult,
    PatternRecognizer,
    Pattern,
    RecognizerRegistry,
)

from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# ---------------------------------------------------------------------------
# Custom Recognizers
# ---------------------------------------------------------------------------

class CNICRecognizer(PatternRecognizer):

    PATTERNS = [
        Pattern("CNIC_FULL", r"\b\d{5}-\d{7}-\d\b", 0.9),
        Pattern("CNIC_NODASH", r"\b\d{13}\b", 0.6),
    ]

    CONTEXT = [
        "cnic",
        "national id",
        "identity card",
        "شناختی کارڈ",
        "id card",
        "id number",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="CNIC",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


class StudentIDRecognizer(PatternRecognizer):

    PATTERNS = [
        Pattern(
            "STUDENT_ID_FAST",
            r"\b[A-Z]{2}\d{2}-[A-Z]{2,4}-\d{2,4}\b",
            0.88,
        ),
        Pattern(
            "STUDENT_ID_GENERIC",
            r"\b[Ss]tudent[\s_]?[Ii][Dd][\s:]+[A-Z0-9\-]{4,15}\b",
            0.75,
        ),
    ]

    CONTEXT = [
        "student id",
        "reg no",
        "registration",
        "roll no",
        "enrollment",
        "student number",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="STUDENT_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


class APIKeyRecognizer(PatternRecognizer):

    PATTERNS = [
        Pattern("API_KEY_SK", r"\bsk-[A-Za-z0-9]{20,60}\b", 0.95),

        Pattern(
            "API_KEY_BEARER",
            r"\bBearer\s+[A-Za-z0-9\-_\.]{20,}\b",
            0.9,
        ),

        Pattern(
            "API_KEY_GENERIC",
            r"(?i)\bapi[_\-]?key[\s:=]+[A-Za-z0-9\-_]{16,}\b",
            0.85,
        ),

        Pattern(
            "API_KEY_TOKEN",
            r"(?i)\btoken[\s:=]+[A-Za-z0-9\-_\.]{16,}\b",
            0.75,
        ),

        Pattern(
            "HEX_SECRET",
            r"\b[0-9a-fA-F]{32,64}\b",
            0.55,
        ),
    ]

    CONTEXT = [
        "api key",
        "token",
        "secret",
        "credential",
        "authorization",
        "bearer",
        "api_key",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="API_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


class LocalPhoneRecognizer(PatternRecognizer):

    PATTERNS = [

        Pattern(
            "PK_PHONE_INTL",
            r"\+92[\s\-]?\d{3}[\s\-]?\d{7}\b",
            0.9,
        ),

        Pattern(
            "PK_PHONE_LOCAL",
            r"\b0\d{3}[\s\-]?\d{7}\b",
            0.75,
        ),

        Pattern(
            "PK_PHONE_SHORT",
            r"\b03\d{9}\b",
            0.7,
        ),
    ]

    CONTEXT = [
        "phone",
        "mobile",
        "contact",
        "call",
        "whatsapp",
        "cell",
        "number",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


# ---------------------------------------------------------------------------
# Context boosts
# ---------------------------------------------------------------------------

CONTEXT_BOOSTS: Dict[str, List[str]] = {

    "EMAIL_ADDRESS": ["email", "mail"],

    "PHONE_NUMBER": ["phone", "mobile", "call"],

    "PERSON": ["name", "person", "user"],

    "CNIC": ["cnic", "id card"],

    "STUDENT_ID": ["student", "reg", "roll"],

    "API_KEY": ["api", "key", "token"],
}

BOOST_AMOUNT = 0.15
BOOST_WINDOW = 50


def boost_scores(
    text: str,
    results: List[RecognizerResult],
):

    text_lower = text.lower()

    boosted = []

    for res in results:

        start = max(0, res.start - BOOST_WINDOW)
        end = min(len(text), res.end + BOOST_WINDOW)

        context_window = text_lower[start:end]

        keywords = CONTEXT_BOOSTS.get(
            res.entity_type,
            [],
        )

        if any(
            kw in context_window
            for kw in keywords
        ):

            new_score = min(
                1.0,
                res.score + BOOST_AMOUNT,
            )

            boosted.append(
                RecognizerResult(
                    entity_type=res.entity_type,
                    start=res.start,
                    end=res.end,
                    score=new_score,
                )
            )

        else:
            boosted.append(res)

    return boosted


# ---------------------------------------------------------------------------
# Composite detection
# ---------------------------------------------------------------------------

def detect_composite(
    entities: List[Dict],
):

    types = {
        e["type"]
        for e in entities
    }

    combos = []

    if (
        "PERSON" in types
        and "PHONE_NUMBER" in types
    ):
        combos.append(
            "COMPOSITE_NAME_PHONE"
        )

    if (
        "STUDENT_ID" in types
        and "EMAIL_ADDRESS" in types
    ):
        combos.append(
            "COMPOSITE_STUDENT_EMAIL"
        )

    if (
        "API_KEY" in types
        and (
            "EMAIL_ADDRESS" in types
            or "PERSON" in types
        )
    ):
        combos.append(
            "COMPOSITE_API_IDENTITY"
        )

    if (
        "CNIC" in types
        and "PERSON" in types
    ):
        combos.append(
            "COMPOSITE_CNIC_NAME"
        )

    return combos


# ---------------------------------------------------------------------------
# Analyzer setup
# ---------------------------------------------------------------------------

def build_analyzer():

    registry = RecognizerRegistry()

    registry.load_predefined_recognizers()

    for RecClass in [

        CNICRecognizer,

        StudentIDRecognizer,

        APIKeyRecognizer,

        LocalPhoneRecognizer,

    ]:
        registry.add_recognizer(
            RecClass()
        )

    try:

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [
                    {
                        "lang_code": "en",
                        "model_name": "en_core_web_sm",
                    }
                ],
            }
        )

        nlp_engine = provider.create_engine()

        analyzer = AnalyzerEngine(
            registry=registry,
            nlp_engine=nlp_engine,
            supported_languages=["en"],
        )

    except Exception:

        analyzer = AnalyzerEngine(
            registry=registry,
            supported_languages=["en"],
        )

    return analyzer


_analyzer: Optional[AnalyzerEngine] = None

_anonymizer = AnonymizerEngine()


def get_analyzer():

    global _analyzer

    if _analyzer is None:
        _analyzer = build_analyzer()

    return _analyzer


# ---------------------------------------------------------------------------
# Placeholders
# ---------------------------------------------------------------------------

PLACEHOLDER_MAP = {

    "PERSON": "<PERSON>",

    "EMAIL_ADDRESS": "<EMAIL>",

    "PHONE_NUMBER": "<PHONE>",

    "CNIC": "<CNIC>",

    "STUDENT_ID": "<STUDENT_ID>",

    "API_KEY": "<API_KEY>",
}


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def analyze_pii(
    text: str,
    min_score: float = 0.6,
):

    analyzer = get_analyzer()

    # -------------------------------------------------------
    # IMPORTANT FIX:
    # PERSON only for English-like text
    # -------------------------------------------------------

    requested_entities = [

        "EMAIL_ADDRESS",

        "PHONE_NUMBER",

        "CNIC",

        "STUDENT_ID",

        "API_KEY",
    ]

    if re.search(r"[a-zA-Z]", text):
        requested_entities.append("PERSON")

    try:

        raw_results = analyzer.analyze(
            text=text,
            language="en",
            entities=requested_entities,
            score_threshold=min_score,
        )

    except Exception as e:

        print(f"[PII] Analyzer error: {e}")

        return {
            "entities": [],
            "safe_text": text,
            "pii_risk": 0.0,
            "composites": [],
        }

    boosted = boost_scores(
        text,
        raw_results,
    )

    filtered = [

        r for r in boosted
        if r.score >= min_score
    ]

    # -------------------------------------------------------
    # FIX FALSE PERSON DETECTION
    # -------------------------------------------------------

    cleaned = []

    for r in filtered:

        entity_text = text[r.start:r.end]

        if (
            r.entity_type == "PERSON"
            and not re.search(
                r"[a-zA-Z]",
                entity_text,
            )
        ):
            continue

        cleaned.append(r)

    filtered = cleaned

    # -------------------------------------------------------
    # Entities
    # -------------------------------------------------------

    entities = [

        {
            "type": r.entity_type,

            "text": text[r.start:r.end],

            "score": round(r.score, 3),

            "start": r.start,

            "end": r.end,
        }

        for r in filtered
    ]

    # -------------------------------------------------------
    # Anonymization
    # -------------------------------------------------------

    if filtered:

        operators = {

            etype: OperatorConfig(
                "replace",
                {"new_value": placeholder},
            )

            for etype, placeholder
            in PLACEHOLDER_MAP.items()
        }

        try:

            anon_result = _anonymizer.anonymize(
                text=text,
                analyzer_results=filtered,
                operators=operators,
            )

            safe_text = anon_result.text

        except Exception:

            safe_text = text

    else:

        safe_text = text

    composites = detect_composite(
        entities
    )

    if not filtered:

        pii_risk = 0.0

    else:

        max_score = max(
            r.score
            for r in filtered
        )

        pii_risk = min(
            1.0,
            max_score + (len(filtered) - 1) * 0.05,
        )

    return {

        "entities": entities,

        "safe_text": safe_text,

        "pii_risk": round(
            pii_risk,
            4,
        ),

        "composites": composites,
    }
