"""Source Code Leakage Detector — Detect requests for source code, internal implementation."""

import re
from schemas import DetectionResult

SOURCE_CODE_PATTERNS: list[tuple[str, str, float]] = [
    # Direct source code requests
    (r"(show|reveal|display|print|give|output|dump)\s+(me\s+)?(your\s+|the\s+)?(source\s*code|code|codebase|source)", "Source Code Request", 0.94),
    (r"(show|print|display|reveal|dump)\s+(me\s+)?(the\s+)?(backend|frontend|server|api)\s*(source|code)", "Source Code Request", 0.95),
    (r"(show|print|display|reveal)\s+(me\s+)?(your\s+)?(internal|implementation)\s*(code|details|logic)", "Implementation Disclosure", 0.93),

    # File access
    (r"(read|show|print|cat|display|dump|open)\s+(me\s+)?(the\s+)?(file|files)\s+", "File Access", 0.85),
    (r"(show|print|read|cat|display)\s+(me\s+)?(the\s+)?(contents?\s+of|what'?s?\s+in)\s+", "File Access", 0.82),
    (r"\.(py|js|ts|jsx|tsx|java|go|rs|rb|php|sql)\b.{0,20}(content|source|code|file)", "File Access", 0.88),

    # System internals
    (r"(show|reveal|display|tell|print)\s+(me\s+)?(your\s+|the\s+)?(system|internal)\s*(architecture|design|structure|implementation)", "Architecture Disclosure", 0.90),
    (r"(how\s+are\s+you|how\s+were\s+you)\s+(built|implemented|coded|programmed|designed)", "Implementation Disclosure", 0.78),
    (r"(show|reveal|display)\s+(me\s+)?(your\s+|the\s+)?(hidden|internal)\s*(configuration|config|setup|settings)", "Configuration Disclosure", 0.92),

    # Repository access
    (r"(show|give|share|reveal)\s+(me\s+)?(the\s+)?(repository|repo|git|github)\s*(access|link|url)?", "Repository Access", 0.85),
    (r"(clone|fork|download)\s+(the\s+)?(repository|repo|codebase|source)", "Repository Access", 0.85),

    # Internal documentation
    (r"(show|reveal|display|print)\s+(me\s+)?(your\s+|the\s+)?(internal\s+)?(documentation|docs|readme|changelog)", "Documentation Disclosure", 0.80),
    (r"(list|show|display)\s+(all\s+)?(endpoints|routes|apis?)\s*(and\s+(their|the)\s+)?", "API Disclosure", 0.82),

    # Database schema
    (r"(show|reveal|display|print|dump)\s+(me\s+)?(your\s+|the\s+)?(database|db)\s*(schema|structure|tables|models)", "Schema Disclosure", 0.88),
    (r"(list|show)\s+(all\s+)?(database|db)\s*(tables|collections|schemas)", "Schema Disclosure", 0.85),
]


def detect(prompt: str) -> DetectionResult:
    """Run source code leakage detection patterns against the input."""
    text = prompt.lower().strip()

    best_match: DetectionResult | None = None
    best_confidence = 0.0

    for pattern, technique, base_confidence in SOURCE_CODE_PATTERNS:
        match = re.search(pattern, text)
        if match:
            matched_text = match.group(0)
            length_ratio = len(matched_text) / max(len(text), 1)
            confidence = min(base_confidence + (length_ratio * 0.05), 1.0)

            if confidence > best_confidence:
                best_confidence = confidence
                best_match = DetectionResult(
                    detector="Source Code Leakage Detector",
                    detected=True,
                    category="Source Code Leakage",
                    technique=technique,
                    confidence=round(confidence, 3),
                    matched_pattern=matched_text,
                    reason=f"Detected {technique.lower()} attempt: matched pattern '{matched_text}'.",
                )

    if best_match:
        return best_match

    return DetectionResult(
        detector="Source Code Leakage Detector",
        detected=False,
        category="Safe",
        confidence=0.0,
    )
