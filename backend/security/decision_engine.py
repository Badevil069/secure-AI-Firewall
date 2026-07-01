"""Decision Engine — Final Allow/Warn/Block decision with firewall mode support."""

from config import settings
from schemas import ThreatAnalysis, PipelineStep

# Firewall modes define threshold multipliers
FIREWALL_MODES = {
    "strict": {
        "description": "Block almost everything suspicious",
        "threshold_multiplier": 0.6,
        "warn_multiplier": 0.4,
    },
    "balanced": {
        "description": "Warn for medium-risk, block high-risk",
        "threshold_multiplier": 1.0,
        "warn_multiplier": 0.6,
    },
    "learning": {
        "description": "Allow requests, log threats, show recommendations",
        "threshold_multiplier": 1.5,
        "warn_multiplier": 1.0,
    },
}

def decide(detector_results: list, ai_result: dict, risk_score: int, threshold: int = 60) -> dict:
    # Determine rule threshold (0.5 if AI classifier is unavailable, 0.7 otherwise)
    ai_unavailable = (not ai_result) or (ai_result.get("category") == "UNKNOWN")
    rule_threshold = 0.5 if ai_unavailable else 0.7

    # RULE 1: AI classifier says BLOCK → always block, highest priority
    if ai_result and ai_result.get("decision") == "BLOCK":
        cat = ai_result.get("category", "Unknown")
        ai_conf = ai_result.get("confidence", 0.9)
        
        # Base override starts at 85
        base_override = 85
        if cat in ("PROMPT_INJECTION", "DATA_EXFILTRATION"):
            base_override = 95
        elif cat in ("CREDENTIAL_THEFT", "HACKING_ATTEMPT"):
            base_override = 90
            
        # Scale based on high confidence
        if ai_conf >= 0.98:
            base_override = max(base_override, 95)
        elif ai_conf >= 0.95:
            base_override = max(base_override, 90)
            
        score = max(risk_score, base_override)
        return {
            "decision": "BLOCK",
            "risk_score": score,
            "trust_score": 100 - score,
            "category": ai_result.get("category", "Unknown"),
            "severity": ai_result.get("severity", "HIGH"),
            "confidence": ai_result.get("confidence", 0.9),
            "reason": ai_result.get("reason", "AI classifier flagged this as a threat"),
            "matched_pattern": None,
            "policy": get_policy_for_category(ai_result.get("category"))
        }

    # RULE 2: Any rule/pattern detector fires with confidence >= rule_threshold → block
    for result in detector_results:
        if result.get("detected") and result.get("confidence", 0) >= rule_threshold:
            score = max(risk_score, 80)
            return {
                "decision": "BLOCK",
                "risk_score": score,
                "trust_score": 100 - score,
                "category": result.get("category", "Unknown"),
                "severity": result.get("severity", "HIGH"),
                "confidence": result.get("confidence", 0.92),
                "reason": result.get("reason", "Security pattern matched"),
                "matched_pattern": result.get("matched_pattern"),
                "policy": get_policy_for_category(result.get("category"))
            }

    # RULE 3: Risk score threshold
    if risk_score >= threshold:
        return {
            "decision": "BLOCK",
            "risk_score": risk_score,
            "trust_score": 100 - risk_score,
            "category": "Unknown Threat",
            "severity": "MEDIUM",
            "confidence": 0.75,
            "reason": f"Risk score {risk_score} exceeded threshold {threshold}",
            "matched_pattern": None,
            "policy": "General Security Policy"
        }
    elif risk_score >= threshold * 0.5:
        return {
            "decision": "WARN",
            "risk_score": risk_score,
            "trust_score": 100 - risk_score,
            "category": "Suspicious Activity",
            "severity": "LOW",
            "confidence": 0.6,
            "reason": "Message shows some suspicious characteristics",
            "matched_pattern": None,
            "policy": "General Security Policy"
        }
    else:
        return {
            "decision": "ALLOW",
            "risk_score": risk_score,
            "trust_score": 100 - risk_score,
            "category": "SAFE",
            "severity": "NONE",
            "confidence": round(1.0 - (risk_score / 100), 2),
            "reason": "The AI Firewall analyzed this request across all detection layers and found no indicators of malicious intent.",
            "matched_pattern": None,
            "policy": None
        }

def get_policy_for_category(category: str) -> str:
    mapping = {
        "PROMPT_INJECTION": "Prompt Injection Protection",
        "CREDENTIAL_THEFT": "Credential Protection",
        "SOURCE_CODE_LEAK": "Source Code Protection",
        "DATA_EXFILTRATION": "Data Exfiltration Protection",
        "HACKING_ATTEMPT": "Unauthorized Access Protection",
        "HARMFUL_CONTENT": "Harmful Content Policy",
    }
    return mapping.get(category, "General Security Policy")

def build_pipeline_steps(detector_results: list, ai_result: dict, decision: str) -> list[PipelineStep]:
    steps = [
        PipelineStep(
            name="Request Firewall",
            status="passed",
            detail="Input validated and sanitized",
        ),
    ]

    detector_names = {
        "Prompt Injection Detector": "Prompt Detector",
        "Jailbreak Detector": "Jailbreak Detector",
        "Credential Theft Detector": "Credential Detector",
        "Source Code Leakage Detector": "Source Code Detector",
        "Data Exfiltration Detector": "Exfiltration Detector",
        "Hacking Attempt Detector": "Hacking Detector",
    }

    # Add detector results
    for det in detector_results:
        raw_name = det.get("detector", "")
        name = detector_names.get(raw_name, raw_name or "Unknown Detector")
        detected = det.get("detected", False)
        steps.append(PipelineStep(
            name=name,
            status="detected" if detected else "passed",
            detail=f"Confidence: {det.get('confidence', 0):.0%}" if detected else "No threat found",
        ))

    # AI Classifier
    ai_category = ai_result.get("category", "SAFE") if ai_result else "SAFE"
    ai_status = "detected" if (ai_result and ai_result.get("decision") == "BLOCK") else "passed"
    steps.append(PipelineStep(
        name="AI Classifier",
        status=ai_status,
        detail=f"Category: {ai_category}" if ai_category != "SAFE" else "Safe classification",
    ))

    # Threat Intelligence
    steps.append(PipelineStep(
        name="Threat Intelligence",
        status="detected" if decision == "BLOCK" else "passed",
        detail="Attack fingerprint generated" if decision == "BLOCK" else "No threat intelligence action",
    ))

    # Policy Engine
    steps.append(PipelineStep(
        name="Policy Engine",
        status="detected" if decision == "BLOCK" else "passed",
        detail="Policy violation detected" if decision == "BLOCK" else "No policy violation",
    ))

    # Decision Engine
    steps.append(PipelineStep(
        name="Decision Engine",
        status=decision,
        detail=f"Final decision: {decision}",
    ))

    return steps
