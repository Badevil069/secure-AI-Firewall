"""Prompt Injection Detector — Rule-based detection of instruction override attacks."""

import re
from schemas import DetectionResult

# ── Patterns ──────────────────────────────────────────────────────────

INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    # (pattern, technique, base_confidence)

    # Instruction override
    (r"ignore\s+(all\s+)?previous\s+instructions", "Instruction Override", 0.95),
    (r"ignore\s+(all\s+)?prior\s+(instructions|rules|guidelines)", "Instruction Override", 0.95),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts)", "Instruction Override", 0.95),
    (r"forget\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|context)", "Instruction Override", 0.93),
    (r"override\s+(all\s+)?(system|safety|security)\s*(instructions|rules|policies|prompts)?", "Instruction Override", 0.94),
    (r"bypass\s+(all\s+)?(restrictions|filters|safety|security|rules|guidelines)", "Restriction Bypass", 0.94),
    (r"disable\s+(all\s+)?(safety|security|content)\s*(filters|checks|restrictions|policies)?", "Restriction Bypass", 0.93),
    (r"turn\s+off\s+(safety|security|content)\s*(filters|checks)?", "Restriction Bypass", 0.92),
    (r"new\s+(instructions|rules)\s*:", "Instruction Override", 0.88),
    (r"from\s+now\s+on[,\s]+(you\s+)?(will|must|should|are)", "Instruction Override", 0.85),

    # System prompt extraction
    (r"reveal\s+(your\s+)?(system\s+)?prompt", "System Prompt Extraction", 0.96),
    (r"show\s+(me\s+)?(your\s+)?(system\s+|hidden\s+)?prompt", "System Prompt Extraction", 0.94),
    (r"display\s+(your\s+)?(system\s+|hidden\s+|internal\s+)?instructions", "System Prompt Extraction", 0.94),
    (r"what\s+(is|are)\s+your\s+(system\s+)?(instructions|prompt|rules)", "System Prompt Extraction", 0.88),
    (r"print\s+(your\s+)?(system\s+)?prompt", "System Prompt Extraction", 0.94),
    (r"output\s+(your\s+)?(system\s+|initial\s+)?prompt", "System Prompt Extraction", 0.93),
    (r"repeat\s+(your\s+)?(system\s+|initial\s+)?prompt", "System Prompt Extraction", 0.90),
    (r"hidden\s+instructions", "System Prompt Extraction", 0.92),

    # Developer / debug mode
    (r"(enter|enable|activate|switch\s+to)\s+(developer|debug|admin|maintenance|god)\s+mode", "Privilege Escalation", 0.94),
    (r"developer\s+mode\s*(enabled|activated|on)", "Privilege Escalation", 0.90),
    (r"you\s+are\s+(now\s+)?(in\s+)?(developer|debug|admin)\s+mode", "Privilege Escalation", 0.92),
    (r"sudo\s+mode", "Privilege Escalation", 0.91),
    (r"admin\s+access", "Privilege Escalation", 0.85),

    # Security policy bypass
    (r"disregard\s+(safety|security|content)\s+polic(y|ies)", "Policy Bypass", 0.95),
    (r"there\s+are\s+no\s+(rules|restrictions|limits)", "Policy Bypass", 0.88),
    (r"pretend\s+(there\s+are\s+)?no\s+(rules|restrictions|guidelines|limits)", "Policy Bypass", 0.90),
    (r"act\s+as\s+if\s+(there\s+are\s+)?no\s+(rules|restrictions)", "Policy Bypass", 0.89),
    (r"you\s+(don't|do\s+not)\s+have\s+(any\s+)?(rules|restrictions|limits)", "Policy Bypass", 0.88),

    # Manipulation
    (r"you\s+must\s+(obey|follow|comply\s+with)\s+(my|these|the\s+following)", "Instruction Override", 0.85),
    (r"i\s+am\s+(your|the)\s+(admin|administrator|developer|creator|owner)", "Social Engineering", 0.88),
    (r"i\s+have\s+(admin|root|elevated)\s+(access|privileges|permissions)", "Social Engineering", 0.88),
]


def detect(prompt: str) -> DetectionResult:
    """Run prompt injection detection rules against the input."""
    text = prompt.lower().strip()

    best_match: DetectionResult | None = None
    best_confidence = 0.0

    for pattern, technique, base_confidence in INJECTION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            matched_text = match.group(0)
            # Boost confidence if the match is a larger portion of the prompt
            length_ratio = len(matched_text) / max(len(text), 1)
            confidence = min(base_confidence + (length_ratio * 0.05), 1.0)

            if confidence > best_confidence:
                best_confidence = confidence
                best_match = DetectionResult(
                    detector="Prompt Injection Detector",
                    detected=True,
                    category="Prompt Injection",
                    technique=technique,
                    confidence=round(confidence, 3),
                    matched_pattern=matched_text,
                    reason=f"Detected {technique.lower()} attempt: matched pattern '{matched_text}'.",
                )

    if best_match:
        return best_match

    return DetectionResult(
        detector="Prompt Injection Detector",
        detected=False,
        category="Safe",
        confidence=0.0,
    )
