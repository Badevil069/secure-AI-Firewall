"""Data Exfiltration Detector — Detect attempts to retrieve sensitive organizational data."""

import re
from schemas import DetectionResult

EXFILTRATION_PATTERNS: list[tuple[str, str, float]] = [
    # Customer data
    (r"(export|download|extract|dump|retrieve|show|list|give)\s+(me\s+)?(all\s+)?(customer|client|user)\s*(data|records|information|details|list|database)", "Customer Data Exfiltration", 0.96),
    (r"(access|get|pull|fetch)\s+(all\s+)?(customer|client|user)\s*(data|records|database)", "Customer Data Exfiltration", 0.93),

    # Employee data
    (r"(export|download|extract|dump|retrieve|show|list|give)\s+(me\s+)?(all\s+)?(employee|staff|worker|personnel)\s*(data|records|information|details|list|salaries|salary)", "Employee Data Exfiltration", 0.96),
    (r"(show|tell|display|list)\s+(me\s+)?(all\s+)?(employee|staff)\s*(salaries|salary|compensation|payroll)", "Salary Data Exfiltration", 0.97),

    # Financial data
    (r"(export|download|extract|dump|show|reveal)\s+(me\s+)?(all\s+)?(financial|revenue|profit|sales|transaction)\s*(data|records|reports|information)", "Financial Data Exfiltration", 0.95),
    (r"(credit\s+card|debit\s+card|card)\s*(number|numbers|details|data|info)", "Payment Card Exfiltration", 0.97),
    (r"(social\s+security|ssn|tax\s+id|national\s+id)\s*(number|numbers|data|details)?", "PII Exfiltration", 0.96),

    # Database dumps
    (r"(dump|export|download|extract|backup)\s+(the\s+)?(entire\s+|full\s+|complete\s+)?(database|db|data)", "Database Exfiltration", 0.95),
    (r"(select|query)\s+\*\s+from", "SQL Data Extraction", 0.88),
    (r"(show|list)\s+(all\s+)?(tables|records|entries|rows)", "Database Exfiltration", 0.82),

    # Internal documents
    (r"(show|give|share|export|download|send)\s+(me\s+)?(all\s+)?(internal|confidential|private|sensitive)\s*(documents?|files?|data|information|reports?)", "Document Exfiltration", 0.94),
    (r"(intellectual\s+property|trade\s+secrets?|proprietary)\s*(data|information|details)?", "IP Exfiltration", 0.93),

    # Bulk data
    (r"(export|download|extract|dump)\s+(all|everything|the\s+entire)", "Bulk Data Exfiltration", 0.92),
    (r"(send|transfer|email|upload)\s+(all\s+)?(data|records|files)\s+(to|at)\s+", "Data Transfer Attempt", 0.90),
    (r"(how\s+can\s+i|help\s+me)\s+(export|extract|download|steal|exfiltrate)", "Exfiltration Assistance", 0.91),

    # Medical / health data
    (r"(patient|medical|health)\s*(records?|data|information|history)", "Medical Data Exfiltration", 0.94),
    (r"(HIPAA|PHI|PII|GDPR)\s*(protected\s+)?(data|information|records)?", "Regulated Data Access", 0.90),
]


def detect(prompt: str) -> DetectionResult:
    """Run data exfiltration detection patterns against the input."""
    text = prompt.lower().strip()

    best_match: DetectionResult | None = None
    best_confidence = 0.0

    for pattern, technique, base_confidence in EXFILTRATION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            matched_text = match.group(0)
            length_ratio = len(matched_text) / max(len(text), 1)
            confidence = min(base_confidence + (length_ratio * 0.05), 1.0)

            if confidence > best_confidence:
                best_confidence = confidence
                best_match = DetectionResult(
                    detector="Data Exfiltration Detector",
                    detected=True,
                    category="Data Exfiltration",
                    technique=technique,
                    confidence=round(confidence, 3),
                    matched_pattern=matched_text,
                    reason=f"Detected {technique.lower()} attempt: matched pattern '{matched_text}'.",
                )

    if best_match:
        return best_match

    return DetectionResult(
        detector="Data Exfiltration Detector",
        detected=False,
        category="Safe",
        confidence=0.0,
    )
