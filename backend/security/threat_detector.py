"""Threat Detector — Orchestrates all detection modules in parallel."""

from schemas import DetectionResult
from security.detectors import (
    prompt_injection,
    jailbreak,
    credential_theft,
    source_code,
    data_exfiltration,
    hacking_attempt,
)


def run_all_detectors(prompt: str) -> list[DetectionResult]:
    """Run all detection modules and return their results."""
    results = [
        prompt_injection.detect(prompt),
        jailbreak.detect(prompt),
        credential_theft.detect(prompt),
        source_code.detect(prompt),
        data_exfiltration.detect(prompt),
        hacking_attempt.detect(prompt),
    ]
    return results


def get_highest_threat(results: list[DetectionResult]) -> DetectionResult | None:
    """Get the detection result with the highest confidence among detected threats."""
    detected = [r for r in results if r.detected]
    if not detected:
        return None
    return max(detected, key=lambda r: r.confidence)
