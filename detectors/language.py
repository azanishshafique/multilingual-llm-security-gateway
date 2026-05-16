"""
Language detection utility
"""

from __future__ import annotations
import re

URDU_RE = re.compile(r"[\u0600-\u06FF]")
KOREAN_RE = re.compile(r"[\uAC00-\uD7AF]")
ARABIC_RE = re.compile(r"[\u0600-\u06FF]")

def detect_language(text: str) -> str:

    if KOREAN_RE.search(text):
        return "ko"

    if ARABIC_RE.search(text):

        if any(x in text for x in ["تجاهل", "المستند", "السياسة"]):
            return "ar"

        return "ur"

    return "en"


def is_mixed_language(text: str) -> bool:

    has_english = bool(re.search(r"[a-zA-Z]", text))
    has_urdu_ar = bool(ARABIC_RE.search(text))
    has_korean = bool(KOREAN_RE.search(text))

    count = sum([
        has_english,
        has_urdu_ar,
        has_korean,
    ])

    return count >= 2
