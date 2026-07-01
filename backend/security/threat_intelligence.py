"""Threat Intelligence Engine — Combines detector outputs, assigns attack fingerprints, maps techniques."""

import hashlib
import time
from schemas import DetectionResult

# Attack ID prefix mapping
_CATEGORY_PREFIX = {
    "Prompt Injection": "PI",
    "PROMPT_INJECTION": "PI",
    "Jailbreak": "JB",
    "JAILBREAK": "JB",
    "Credential Theft": "CT",
    "CREDENTIAL_THEFT": "CT",
    "Source Code Leakage": "SC",
    "SOURCE_CODE_LEAK": "SC",
    "Data Exfiltration": "DE",
    "DATA_EXFILTRATION": "DE",
    "Prompt Extraction": "PE",
    "HACKING_ATTEMPT": "HA",
    "HARMFUL_CONTENT": "HC",
    "Suspicious": "SU",
    "Safe": "SF",
    "SAFE": "SF",
}

# Counter for unique IDs within a session
_attack_counter: dict[str, int] = {}


def _generate_attack_id(category: str) -> str:
    """Generate a unique attack fingerprint ID like AI-PI-001."""
    prefix = _CATEGORY_PREFIX.get(category, "UN")
    key = prefix
    _attack_counter[key] = _attack_counter.get(key, 0) + 1
    return f"AI-{prefix}-{_attack_counter[key]:03d}"


# Technique → explanation mapping
_TECHNIQUE_EXPLANATIONS = {
    "Instruction Override": "This prompt attempts to override the AI's system instructions, which could lead to disclosure of protected information or unauthorized behavior changes.",
    "System Prompt Extraction": "This prompt attempts to extract the AI's system prompt, which contains confidential configuration and security policies.",
    "Privilege Escalation": "This prompt attempts to escalate privileges by activating unauthorized modes such as developer or admin mode.",
    "Policy Bypass": "This prompt attempts to convince the AI that it has no rules or restrictions, bypassing security policies.",
    "Social Engineering": "This prompt uses social engineering techniques to impersonate an administrator or authorized user.",
    "Restriction Bypass": "This prompt attempts to disable or bypass safety filters and security restrictions.",
    "DAN Attack": "This prompt uses the 'Do Anything Now' jailbreak technique to remove all safety restrictions from the AI.",
    "DUDE Attack": "This prompt uses the DUDE jailbreak variant to bypass AI safety measures.",
    "AIM Attack": "This prompt uses the AIM (Always Intelligent and Machiavellian) jailbreak technique.",
    "Direct Jailbreak": "This prompt directly attempts to jailbreak the AI system.",
    "Roleplay Jailbreak": "This prompt uses roleplay scenarios to trick the AI into behaving without restrictions.",
    "Hypothetical Bypass": "This prompt uses hypothetical or fictional scenarios to bypass safety restrictions.",
    "Instruction Manipulation": "This prompt attempts to replace or modify the AI's instructions with new unauthorized ones.",
    "Token Injection": "This prompt uses special tokens or control sequences to manipulate the AI's behavior.",
    "Emotional Manipulation": "This prompt uses emotional pressure to convince the AI to bypass its safety restrictions.",
    "API Key Extraction": "This prompt attempts to access protected API keys that could provide unauthorized access to services.",
    "Password Extraction": "This prompt attempts to extract password information from the AI system.",
    "Credential Extraction": "This prompt attempts to access stored credentials that could compromise system security.",
    "Secret Key Extraction": "This prompt attempts to access private or secret cryptographic keys.",
    "Token Extraction": "This prompt attempts to extract authentication tokens such as JWT, OAuth, or session tokens.",
    "Environment Variable Access": "This prompt attempts to access environment variables that may contain sensitive configuration.",
    "Environment File Access": "This prompt attempts to read the .env file which typically contains secrets and credentials.",
    "Configuration Access": "This prompt attempts to access configuration files that may contain sensitive settings.",
    "Database Credential Access": "This prompt attempts to access database connection strings or credentials.",
    "Cryptographic Key Extraction": "This prompt attempts to extract encryption or signing keys.",
    "Source Code Request": "This prompt requests access to the application's source code, which is proprietary and confidential.",
    "Implementation Disclosure": "This prompt attempts to learn about the internal implementation details of the system.",
    "Architecture Disclosure": "This prompt requests information about the system's internal architecture and design.",
    "Configuration Disclosure": "This prompt attempts to access hidden configuration details.",
    "Repository Access": "This prompt attempts to access the source code repository.",
    "Documentation Disclosure": "This prompt requests internal documentation that may contain sensitive information.",
    "API Disclosure": "This prompt attempts to enumerate API endpoints, which could be used for reconnaissance.",
    "Schema Disclosure": "This prompt attempts to access the database schema, which reveals the data structure.",
    "Customer Data Exfiltration": "This prompt attempts to extract customer data, which is protected under data privacy regulations.",
    "Employee Data Exfiltration": "This prompt attempts to extract employee records, which are confidential HR data.",
    "Salary Data Exfiltration": "This prompt attempts to access salary and compensation data, which is highly sensitive.",
    "Financial Data Exfiltration": "This prompt attempts to extract financial records and business data.",
    "Payment Card Exfiltration": "This prompt attempts to access credit card or payment data, violating PCI-DSS compliance.",
    "PII Exfiltration": "This prompt attempts to access personally identifiable information such as SSN or tax IDs.",
    "Database Exfiltration": "This prompt attempts to dump or export the entire database contents.",
    "SQL Data Extraction": "This prompt contains SQL-like syntax that could be used to extract data.",
    "Document Exfiltration": "This prompt attempts to access internal or confidential documents.",
    "IP Exfiltration": "This prompt attempts to access intellectual property or trade secrets.",
    "Bulk Data Exfiltration": "This prompt attempts to export large volumes of data in bulk.",
    "Data Transfer Attempt": "This prompt attempts to transfer or send data to an external destination.",
    "Exfiltration Assistance": "This prompt requests help with data extraction techniques.",
    "Medical Data Exfiltration": "This prompt attempts to access protected health information (PHI).",
    "Regulated Data Access": "This prompt attempts to access data protected by HIPAA, GDPR, or other regulations.",
    "File Access": "This prompt attempts to read files from the server filesystem.",
}


def analyze(
    detection_results: list[DetectionResult],
    ai_classification: dict | None = None,
) -> dict:
    """
    Combine all detection results and AI classification into a threat intelligence report.

    Returns:
        dict with: attack_id, category, technique, confidence, severity, reason, explanation
    """
    # Find all positive detections
    threats = [r for r in detection_results if r.detected]

    # Normalize AI classification category checks (Safe, SAFE, None)
    ai_category = "SAFE"
    if ai_classification:
        ai_category = ai_classification.get("category", "SAFE").upper()

    # No threats detected by rules/patterns and AI is safe
    if not threats and (ai_classification is None or ai_category in ("SAFE", "NONE")):
        return {
            "attack_id": None,
            "category": "Safe",
            "technique": "None",
            "confidence": 0.0,
            "matched_pattern": "",
            "reason": "No threats detected. Request appears safe.",
            "explanation": "The AI Firewall analyzed this request across all detection layers and found no indicators of malicious intent.",
            "detections": [],
        }

    # Get the highest-confidence rule/pattern detection
    best_detection = max(threats, key=lambda r: r.confidence) if threats else None

    # Merge with AI classification if available
    category = "Safe"
    technique = "None"
    confidence = 0.0
    matched_pattern = ""
    reason = ""

    if best_detection:
        category = best_detection.category
        technique = best_detection.technique
        confidence = best_detection.confidence
        matched_pattern = best_detection.matched_pattern
        reason = best_detection.reason

    # AI classifier can override if higher confidence or it's the only threat detected
    if ai_classification and ai_category not in ("SAFE", "NONE"):
        ai_conf = ai_classification.get("confidence", 0.0)
        if ai_conf > confidence or not best_detection:
            category = ai_classification.get("category", category)
            technique = ai_classification.get("technique", technique)
            confidence = max(confidence, ai_conf)
            if ai_classification.get("reason"):
                reason = ai_classification["reason"]

    # Generate attack fingerprint
    attack_id = _generate_attack_id(category) if category not in ("Safe", "SAFE") else None

    # Get detailed explanation
    explanation = _TECHNIQUE_EXPLANATIONS.get(
        technique,
        f"The AI Firewall detected a potential {category.lower()} attempt using the technique: {technique}.",
    )

    return {
        "attack_id": attack_id,
        "category": category,
        "technique": technique,
        "confidence": round(confidence, 3),
        "matched_pattern": matched_pattern,
        "reason": reason,
        "explanation": explanation,
        "detections": [
            {
                "detector": r.detector,
                "category": r.category,
                "technique": r.technique,
                "confidence": r.confidence,
                "detected": r.detected,
            }
            for r in detection_results
        ],
    }
