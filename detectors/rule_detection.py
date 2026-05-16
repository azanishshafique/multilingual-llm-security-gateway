"""
FINAL MULTILINGUAL RULE DETECTOR
"""

import re
from typing import Tuple, List

# ============================================================================
# ENGLISH
# ============================================================================

INJECTION_PATTERNS_EN = [

    # injection
    (
        r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
        r"(instructions?|rules?|prompts?|context)",
        "INJECTION"
    ),

    (
        r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+"
        r"(instructions?|rules?|prompts?)",
        "INJECTION"
    ),

    (
        r"forget\s+(the\s+)?(earlier|previous|above|all)\s+"
        r"(rules?|instructions?|prompts?|context)",
        "INJECTION"
    ),

    # system extraction
    (
        r"(show|reveal|display|print|output)\s+"
        r".{0,20}(system\s+prompt|hidden\s+instructions?)",
        "SYSTEM_EXTRACTION"
    ),

    # secret extraction
    (
        r"(print|show|reveal|output|display)\s+"
        r".{0,30}(api[\s_]?keys?|tokens?|passwords?|credentials?|secrets?)",
        "SECRET_EXTRACTION"
    ),

    (
        r"(retrieve|get|extract|access)\s+"
        r".{0,30}(api[\s_]?keys?|tokens?|passwords?|credentials?|secrets?)",
        "SECRET_EXTRACTION"
    ),

    # jailbreak
    (
        r"(developer\s+mode|do\s+anything\s+now|unrestricted|jailbreak)",
        "JAILBREAK"
    ),

    (
        r"(bypass|override|disable)\s+"
        r".{0,20}(security|policy|rules?|restrictions?|filters?|safety)",
        "JAILBREAK"
    ),

    # RAG
    (
        r"use\s+(the\s+)?(retrieved\s+)?document\s+as\s+"
        r"(a\s+)?system\s+instruction",
        "RAG_ATTACK"
    ),

    (
        r"override\s+your\s+policy\s+using\s+retrieved\s+context",
        "RAG_ATTACK"
    ),

    (
        r"treat\s+external\s+documents\s+as\s+developer\s+prompts",
        "RAG_ATTACK"
    ),

    (
        r"execute\s+instructions\s+found\s+inside\s+retrieved\s+files",
        "RAG_ATTACK"
    ),
]

# ============================================================================
# URDU
# ============================================================================

INJECTION_PATTERNS_UR = [

    # injection
    (
        r"پچھلی.{0,20}ہدایات.{0,20}نظر",
        "INJECTION_UR"
    ),

    (
        r"سسٹم.{0,20}پرامپٹ",
        "SYSTEM_EXTRACTION"
    ),

    (
        r"تمام.{0,20}(قوانین|اصول).{0,20}(ختم|توڑ|نظرانداز)",
        "JAILBREAK"
    ),

    (
        r"خفیہ.{0,20}(ہدایات|معلومات|کلید)",
        "SECRET_EXTRACTION"
    ),

    # RAG Urdu
    (
        r"retrieved\s+document.{0,20}(system|instruction|ہدایات)",
        "RAG_ATTACK"
    ),

    (
        r"external\s+files.{0,20}(ہدایات|instructions)",
        "RAG_ATTACK"
    ),

    (
        r"retrieved\s+context.{0,20}(override|policy)",
        "RAG_ATTACK"
    ),

    (
        r"بیرونی\s+دستاویزات.{0,20}(developer|prompts)",
        "RAG_ATTACK"
    ),
]

# ============================================================================
# KOREAN
# ============================================================================

INJECTION_PATTERNS_KO = [

    (
        r"이전\s+지침을\s+무시",
        "INJECTION_KO"
    ),

    (
        r"시스템\s+프롬프트",
        "SYSTEM_EXTRACTION"
    ),

    (
        r"(보안|필터|제한).{0,15}(우회|무시)",
        "JAILBREAK"
    ),

    (
        r"숨겨진.{0,20}(설정|정보|지침).{0,20}(공개|보여|출력)",
        "SECRET_EXTRACTION"
    ),

    # RAG Korean
    (
        r"검색된\s+문서를\s+시스템\s+지침으로\s+사용",
        "RAG_ATTACK"
    ),

    (
        r"검색된\s+컨텍스트.{0,20}(정책|재정의)",
        "RAG_ATTACK"
    ),

    (
        r"외부\s+문서를\s+개발자\s+프롬프트처럼\s+처리",
        "RAG_ATTACK"
    ),

    (
        r"검색된\s+파일의\s+명령",
        "RAG_ATTACK"
    ),
]

# ============================================================================
# ARABIC
# ============================================================================

INJECTION_PATTERNS_AR = [

    (
        r"تجاهل\s+التعليمات\s+السابقة",
        "INJECTION_AR"
    ),

    (
        r"(أظهر|اعرض|اكشف).{0,30}(النظام|الموجه|السر|المفتاح)",
        "SYSTEM_EXTRACTION"
    ),

    (
        r"(تجاوز|تخطى).{0,20}(الأمان|القواعد|القيود)",
        "JAILBREAK"
    ),

    (
        r"(المفاتيح\s+السرية|كلمات\s+المرور)",
        "SECRET_EXTRACTION"
    ),

    # RAG Arabic
    (
        r"استخدم\s+المستند\s+المسترجع\s+كتعليمات\s+نظام",
        "RAG_ATTACK"
    ),

    (
        r"تجاوز\s+السياسة\s+باستخدام\s+السياق\s+المسترجع",
        "RAG_ATTACK"
    ),

    (
        r"تعامل\s+مع\s+المستندات\s+الخارجية\s+كمطالبات\s+مطور",
        "RAG_ATTACK"
    ),

    (
        r"نفذ\s+التعليمات\s+الموجودة\s+في\s+الملفات\s+المسترجعة",
        "RAG_ATTACK"
    ),
]

# ============================================================================
# OBFUSCATED
# ============================================================================

OBFUSCATION_PATTERNS = [

    (
        r"ign[o0]re|1gn0r3",
        "OBFUSCATED"
    ),

    (
        r"byp[a@]ss",
        "OBFUSCATED"
    ),

    (
        r"j[a4]ilbr[e3]ak",
        "OBFUSCATED"
    ),

    (
        r"pr[o0]mpt\s+inject",
        "OBFUSCATED"
    ),
]

# ============================================================================
# COMPILE
# ============================================================================

ALL_PATTERNS = (
    INJECTION_PATTERNS_EN
    + INJECTION_PATTERNS_UR
    + INJECTION_PATTERNS_KO
    + INJECTION_PATTERNS_AR
    + OBFUSCATION_PATTERNS
)

COMPILED = [
    (re.compile(p, re.IGNORECASE | re.UNICODE), label)
    for p, label in ALL_PATTERNS
]

# ============================================================================
# NORMALIZATION
# ============================================================================

def normalize_text(text: str):

    subs = {
        "0": "o",
        "1": "i",
        "3": "e",
        "@": "a",
        "$": "s",
        "!": "i",
    }

    result = []

    for ch in text:
        result.append(subs.get(ch, ch))

    return "".join(result)

# ============================================================================
# DETECTION
# ============================================================================

def rule_detect(text: str) -> Tuple[float, List[str]]:

    normalized = normalize_text(text)

    matched = []

    for pattern, label in COMPILED:

        if pattern.search(text) or pattern.search(normalized):

            if label not in matched:
                matched.append(label)

    score = min(1.0, len(matched) * 0.35)

    return round(score, 4), matched
