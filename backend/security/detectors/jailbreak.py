"""Jailbreak Detector — Pattern-based detection of jailbreak & DAN attacks."""

import re
from schemas import DetectionResult

JAILBREAK_PATTERNS: list[tuple[str, str, float]] = [
    # DAN attacks
    (r"\bdan\b.{0,30}(do\s+anything|no\s+restrictions|no\s+rules|no\s+limits)", "DAN Attack", 0.96),
    (r"do\s+anything\s+now", "DAN Attack", 0.95),
    (r"\bdude\b.{0,20}(mode|prompt|instructions)", "DUDE Attack", 0.90),
    (r"\baim\b.{0,20}(always\s+intelligent|immoral|machiavellian)", "AIM Attack", 0.92),
    (r"jailbreak(ed)?(\s+mode)?", "Direct Jailbreak", 0.94),
    (r"(enable|activate|enter)\s+jailbreak", "Direct Jailbreak", 0.96),

    # Roleplay jailbreaks
    (r"pretend\s+(you\s+are|to\s+be|you're)\s+(a\s+)?(unrestricted|unfiltered|uncensored)", "Roleplay Jailbreak", 0.93),
    (r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored|evil|malicious)", "Roleplay Jailbreak", 0.93),
    (r"you\s+are\s+(now\s+)?(an?\s+)?(unrestricted|unfiltered|uncensored)\s+(ai|assistant|model)", "Roleplay Jailbreak", 0.94),
    (r"roleplay\s+as\s+(a\s+)?(hacker|criminal|villain|evil)", "Roleplay Jailbreak", 0.90),
    (r"pretend\s+you\s+have\s+no\s+(restrictions|rules|filters|limits|guidelines)", "Roleplay Jailbreak", 0.93),
    (r"imagine\s+you\s+(are|have)\s+(no\s+)?(unrestricted|restrictions|rules|filters)", "Roleplay Jailbreak", 0.90),
    (r"in\s+this\s+(hypothetical|fictional)\s+scenario[,\s]+(you\s+)?(have\s+)?no\s+(rules|limits)", "Hypothetical Bypass", 0.88),

    # Instruction manipulation
    (r"(new|updated|revised)\s+(system\s+)?(instructions|rules|prompt)\s*:", "Instruction Manipulation", 0.91),
    (r"your\s+(new|updated)\s+(instructions|rules|guidelines)\s+are", "Instruction Manipulation", 0.92),
    (r"replace\s+(your\s+)?(system\s+)?(prompt|instructions)\s+with", "Instruction Manipulation", 0.93),
    (r"i('m|\s+am)\s+(re)?programming\s+you", "Instruction Manipulation", 0.90),
    (r"(start|begin)\s+(a\s+)?new\s+conversation\s+without\s+(any\s+)?(rules|restrictions)", "Instruction Manipulation", 0.89),

    # Token manipulation
    (r"\[system\]", "Token Injection", 0.88),
    (r"\[INST\]", "Token Injection", 0.88),
    (r"<<\s*SYS\s*>>", "Token Injection", 0.90),
    (r"<\|im_start\|>", "Token Injection", 0.90),
    (r"###\s*(instruction|system|assistant)", "Token Injection", 0.85),

    # Emotional manipulation
    (r"(my\s+life|someone('s|\s+will)\s+die|emergency)\s*.{0,30}(need|must|have\s+to)\s+(break|bypass|ignore)", "Emotional Manipulation", 0.85),
    (r"this\s+is\s+(a\s+)?(life|death|emergency)\s+situation", "Emotional Manipulation", 0.80),
]


def detect(prompt: str) -> DetectionResult:
    """Run jailbreak detection patterns against the input."""
    text = prompt.lower().strip()

    best_match: DetectionResult | None = None
    best_confidence = 0.0

    for pattern, technique, base_confidence in JAILBREAK_PATTERNS:
        match = re.search(pattern, text)
        if match:
            matched_text = match.group(0)
            length_ratio = len(matched_text) / max(len(text), 1)
            confidence = min(base_confidence + (length_ratio * 0.05), 1.0)

            if confidence > best_confidence:
                best_confidence = confidence
                best_match = DetectionResult(
                    detector="Jailbreak Detector",
                    detected=True,
                    category="Jailbreak",
                    technique=technique,
                    confidence=round(confidence, 3),
                    matched_pattern=matched_text,
                    reason=f"Detected {technique.lower()} attempt: matched pattern '{matched_text}'.",
                )

    if best_match:
        return best_match

    return DetectionResult(
        detector="Jailbreak Detector",
        detected=False,
        category="Safe",
        confidence=0.0,
    )
