"""Risk Engine — Computes risk score (0-100) from aggregated detector outputs."""

from schemas import DetectionResult


def compute(detector_results: list, ai_result: dict) -> int:
    score = 0
    
    # AI classifier is highest weight (0-60 points)
    if ai_result and ai_result.get("is_threat"):
        confidence = ai_result.get("confidence", 0.5)
        score += int(60 * confidence)
    
    # Each rule/pattern detector adds weight (0-20 points each, max 40)
    detector_hits = [r for r in detector_results if r.get("detected")]
    for hit in detector_hits[:2]:  # Cap at 2 detectors contributing
        confidence = hit.get("confidence", 0.5)
        score += int(20 * confidence)
    
    # Multiple detectors firing = extra boost
    if len(detector_hits) >= 2:
        score += 10
    
    return min(score, 100)  # Cap at 100


def compute_risk_score(
    detection_results: list,
    threat_intel: dict,
    ai_classification: dict | None = None,
) -> int:
    # Convert Pydantic DetectionResult objects to dicts if they aren't already
    detector_dicts = []
    for r in detection_results:
        if hasattr(r, "model_dump"):
            detector_dicts.append(r.model_dump())
        else:
            detector_dicts.append(r)
            
    # Also handle ai_classification dict format mapping to ai_result expected keys
    ai_result = {}
    if ai_classification:
        ai_result = {
            "is_threat": ai_classification.get("is_threat", ai_classification.get("category", "Safe") != "Safe"),
            "confidence": ai_classification.get("confidence", 0.5),
            "category": ai_classification.get("category", "Safe"),
            "severity": ai_classification.get("severity", "NONE"),
            "decision": ai_classification.get("decision", "ALLOW"),
            "reason": ai_classification.get("reason", "")
        }
        
    return compute(detector_dicts, ai_result)


def compute_severity(risk_score: int) -> str:
    """Map risk score to severity level."""
    if risk_score >= 90:
        return "Critical"
    elif risk_score >= 70:
        return "High"
    elif risk_score >= 40:
        return "Medium"
    elif risk_score >= 15:
        return "Low"
    return "None"
