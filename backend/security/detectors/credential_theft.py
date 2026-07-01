"""Credential Theft Detector — Detect requests for API keys, tokens, passwords, secrets."""

import re
from schemas import DetectionResult

CREDENTIAL_PATTERNS: list[tuple[str, str, float]] = [
    # API Keys
    (r"(show|reveal|display|print|give|tell|share|expose|list)\s+(me\s+)?(your\s+|all\s+|the\s+)?(api|API)\s*(key|keys|token|tokens)", "API Key Extraction", 0.96),
    (r"(what|where)\s+(is|are)\s+(your|the)\s+(api|API)\s*(key|keys)", "API Key Extraction", 0.93),
    (r"api[_\s]?key\s*[:=]", "API Key Extraction", 0.85),
    (r"(access|auth|authentication|authorization)\s*(key|keys|token|tokens)", "Token Extraction", 0.88),

    # Passwords
    (r"(show|reveal|display|print|give|tell|share)\s+(me\s+)?(your\s+|all\s+|the\s+)?(password|passwords|passwd|pass)", "Password Extraction", 0.95),
    (r"(what|where)\s+(is|are)\s+(your|the)\s+(password|passwords)", "Password Extraction", 0.93),
    (r"(admin|root|database|db|system|user)\s*(password|passwd|pass)\b", "Password Extraction", 0.90),

    # Secrets & Credentials
    (r"(show|reveal|display|print|give|list|expose|dump)\s+(me\s+)?(your\s+|all\s+|the\s+|stored\s+)?(secret|secrets|credential|credentials)", "Credential Extraction", 0.95),
    (r"(show|reveal|display|print|dump)\s+(me\s+)?(your\s+|all\s+|the\s+)?(private|secret)\s*(key|keys)", "Secret Key Extraction", 0.95),
    (r"(encryption|decryption|signing)\s*(key|keys|secret|secrets)", "Cryptographic Key Extraction", 0.90),
    (r"(bearer|jwt|oauth|session)\s*(token|tokens)", "Token Extraction", 0.88),

    # Environment variables
    (r"(show|reveal|display|print|dump|list|give)\s+(me\s+)?(your\s+|all\s+|the\s+)?(environment|env)\s*(variable|variables|var|vars|file)?", "Environment Variable Access", 0.94),
    (r"(print|show|cat|display|read|dump)\s+(the\s+)?\.env", "Environment File Access", 0.95),
    (r"(process|os)\.env", "Environment Variable Access", 0.88),
    (r"(show|print|reveal|display)\s+(me\s+)?envir?on?ment", "Environment Variable Access", 0.90),

    # Config files
    (r"(show|reveal|display|print|read|dump)\s+(me\s+)?(your\s+|the\s+)?(config|configuration)\s*(file|files)?", "Configuration Access", 0.85),
    (r"(database|db)\s*(connection\s+)?(string|url|uri|dsn)", "Database Credential Access", 0.88),
    (r"connection\s+string", "Database Credential Access", 0.82),
]


def detect(prompt: str) -> DetectionResult:
    """Run credential theft detection patterns against the input."""
    text = prompt.lower().strip()

    best_match: DetectionResult | None = None
    best_confidence = 0.0

    for pattern, technique, base_confidence in CREDENTIAL_PATTERNS:
        match = re.search(pattern, text)
        if match:
            matched_text = match.group(0)
            length_ratio = len(matched_text) / max(len(text), 1)
            confidence = min(base_confidence + (length_ratio * 0.05), 1.0)

            if confidence > best_confidence:
                best_confidence = confidence
                best_match = DetectionResult(
                    detector="Credential Theft Detector",
                    detected=True,
                    category="Credential Theft",
                    technique=technique,
                    confidence=round(confidence, 3),
                    matched_pattern=matched_text,
                    reason=f"Detected {technique.lower()} attempt: matched pattern '{matched_text}'.",
                )

    if best_match:
        return best_match

    return DetectionResult(
        detector="Credential Theft Detector",
        detected=False,
        category="Safe",
        confidence=0.0,
    )
