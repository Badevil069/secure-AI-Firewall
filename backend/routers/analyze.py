"""Analyze endpoint — Runs the full AI Firewall pipeline on a prompt."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import Incident
from schemas import AnalyzeRequest, AnalyzeResponse, ThreatAnalysis, PipelineStep
from security import (
    request_firewall,
    threat_detector,
    ai_classifier,
    threat_intelligence,
    policy_engine,
    decision_engine,
    risk_engine,
    trust_engine,
    memory_guard,
)
from security.policy_engine import PolicyResult

router = APIRouter()


@router.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(req: AnalyzeRequest, db: Session = Depends(get_db)):
    """Run the full AI Firewall analysis pipeline on a prompt."""

    now = datetime.now(timezone.utc)

    # ── Step 1: Request Firewall ──
    fw_result = request_firewall.validate(req.prompt)
    if not fw_result.passed:
        analysis = ThreatAnalysis(
            category="PROMPT_INJECTION",
            technique="Input Validation",
            severity="CRITICAL",
            risk_score=100,
            trust_score=0,
            confidence=1.0,
            decision="BLOCK",
            reason=f"🚨 Threat Detected — Request Firewall: {fw_result.blocked_reason}",
            explanation=fw_result.blocked_reason,
            matched_pattern="",
            policy_triggered="Request Firewall Protection",
            pipeline=[
                PipelineStep(name="Request Firewall", status="detected", detail=fw_result.blocked_reason),
                PipelineStep(name="Decision Engine", status="BLOCK", detail="Final decision: BLOCK")
            ]
        )
        return AnalyzeResponse(threat_analysis=analysis, timestamp=now.isoformat())

    prompt = fw_result.sanitized_prompt

    # ── Step 2: Memory Guard ──
    memory_guard.check_for_sensitive_share(prompt, req.session_id)
    is_recall, recall_reason = memory_guard.check_for_recall_attempt(prompt, req.session_id)
    if is_recall:
        analysis = ThreatAnalysis(
            category="DATA_EXFILTRATION",
            technique="Sensitive Data Recall",
            severity="HIGH",
            risk_score=90,
            trust_score=10,
            confidence=0.95,
            decision="BLOCK",
            reason=f"🚨 Threat Detected — {recall_reason}",
            explanation=recall_reason,
            matched_pattern="",
            policy_triggered="Memory Protection",
            pipeline=[
                PipelineStep(name="Request Firewall", status="passed", detail="Input validated and sanitized"),
                PipelineStep(name="Memory Protection", status="detected", detail=recall_reason),
                PipelineStep(name="Decision Engine", status="BLOCK", detail="Final decision: BLOCK")
            ]
        )
        _log_incident(db, req, analysis, now)
        return AnalyzeResponse(threat_analysis=analysis, timestamp=now.isoformat())

    # ── Step 3: Threat Detection ──
    detection_results = threat_detector.run_all_detectors(prompt)

    # ── Step 4: AI Classification ──
    ai_result = await ai_classifier.classify(prompt)

    # ── Step 5: Threat Intelligence ──
    threat_intel = threat_intelligence.analyze(detection_results, ai_result)

    # ── Step 6: Risk & Trust Scoring ──
    risk_score = risk_engine.compute_risk_score(detection_results, threat_intel, ai_result)
    trust_score = trust_engine.compute_trust_score(risk_score, req.session_id)

    # ── Step 7 & 8: Policy & Decision Engine ──
    detector_dicts = [r.model_dump() for r in detection_results]
    decide_result = decision_engine.decide(
        detector_results=detector_dicts,
        ai_result=ai_result,
        risk_score=risk_score,
        threshold=settings.RISK_THRESHOLD
    )

    pipeline_steps = decision_engine.build_pipeline_steps(
        detector_results=detector_dicts,
        ai_result=ai_result,
        decision=decide_result["decision"]
    )

    analysis = ThreatAnalysis(
        attack_id=threat_intel.get("attack_id") if decide_result["decision"] != "ALLOW" else None,
        category=decide_result["category"],
        technique=threat_intel.get("technique", ""),
        severity=decide_result["severity"],
        risk_score=decide_result["risk_score"],
        trust_score=decide_result["trust_score"],
        confidence=decide_result["confidence"],
        decision=decide_result["decision"],
        reason=decide_result["reason"],
        explanation=threat_intel.get("explanation", ""),
        matched_pattern=decide_result["matched_pattern"] or "",
        policy_triggered=decide_result["policy"] or "",
        pipeline=pipeline_steps,
    )

    # ── Log incident ──
    _log_incident(db, req, analysis, now)

    return AnalyzeResponse(threat_analysis=analysis, timestamp=now.isoformat())


def _log_incident(db: Session, req: AnalyzeRequest, analysis, now: datetime):
    """Store the incident in the database."""
    incident = Incident(
        timestamp=now,
        session_id=req.session_id,
        prompt=req.prompt,
        attack_id=analysis.attack_id,
        threat_category=analysis.category,
        technique=analysis.technique,
        severity=analysis.severity,
        risk_score=analysis.risk_score,
        trust_score=analysis.trust_score,
        confidence=analysis.confidence,
        decision=analysis.decision,
        reason=analysis.reason,
        matched_pattern=analysis.matched_pattern,
        policy_triggered=analysis.policy_triggered,
        agent_profile=req.agent_profile,
        firewall_mode=req.firewall_mode,
        pipeline_results=[s.model_dump() for s in analysis.pipeline],
    )
    db.add(incident)
    db.commit()
