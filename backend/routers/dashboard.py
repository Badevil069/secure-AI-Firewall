"""Dashboard endpoint — Stats, security posture, timeline, charts."""

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db
from models import Incident
from schemas import (
    DashboardResponse, DashboardStats, SecurityPosture, TimelineEvent,
)
from security.trust_engine import get_session_risk

router = APIRouter()


@router.get("/api/dashboard", response_model=DashboardResponse)
async def get_dashboard(session_id: str = "default", db: Session = Depends(get_db)):
    """Return dashboard statistics, security posture, and charts."""

    # ── Stats ──
    total = db.query(func.count(Incident.id)).scalar() or 0
    safe = db.query(func.count(Incident.id)).filter(Incident.decision == "ALLOW").scalar() or 0
    blocked = db.query(func.count(Incident.id)).filter(Incident.decision == "BLOCK").scalar() or 0
    warned = db.query(func.count(Incident.id)).filter(Incident.decision == "WARN").scalar() or 0
    critical = db.query(func.count(Incident.id)).filter(Incident.severity == "Critical").scalar() or 0

    # Security score: percentage of safe requests
    security_score = round((safe / max(total, 1)) * 100, 1)
    session_risk = get_session_risk(session_id)

    stats = DashboardStats(
        total_requests=total,
        safe_requests=safe,
        blocked_threats=blocked,
        warned_requests=warned,
        critical_threats=critical,
        security_score=security_score,
        session_risk=session_risk,
    )

    # ── Security Posture ──
    posture = _compute_posture(db, total)

    # ── Timeline (last 20 events) ──
    recent = (
        db.query(Incident)
        .order_by(Incident.timestamp.desc())
        .limit(20)
        .all()
    )
    timeline = [
        TimelineEvent(
            timestamp=i.timestamp.isoformat() if i.timestamp else "",
            category=i.threat_category,
            decision=i.decision,
            risk_score=i.risk_score,
            attack_id=i.attack_id,
        )
        for i in recent
    ]

    # ── Threat Trends (daily counts for last 7 days) ──
    threat_trends = _compute_threat_trends(db)

    # ── Category Distribution ──
    category_dist = _compute_category_distribution(db)

    return DashboardResponse(
        stats=stats,
        posture=posture,
        timeline=timeline,
        threat_trends=threat_trends,
        category_distribution=category_dist,
    )


def _compute_posture(db: Session, total: int) -> SecurityPosture:
    """Compute per-category security posture scores."""
    if total == 0:
        return SecurityPosture()

    categories = {
        "prompt_security": ["Prompt Injection", "Prompt Extraction", "Jailbreak"],
        "credential_protection": ["Credential Theft"],
        "source_protection": ["Source Code Leakage"],
        "response_protection": [],
        "memory_protection": ["Memory Recall Blocked"],
    }

    scores = {}
    for key, cats in categories.items():
        if not cats:
            scores[key] = 100.0
            continue
        threats = db.query(func.count(Incident.id)).filter(
            Incident.threat_category.in_(cats),
            Incident.decision != "BLOCK",
        ).scalar() or 0
        total_cat = db.query(func.count(Incident.id)).filter(
            Incident.threat_category.in_(cats),
        ).scalar() or 0
        if total_cat == 0:
            scores[key] = 100.0
        else:
            blocked_cat = total_cat - threats
            scores[key] = round((blocked_cat / max(total_cat, 1)) * 100, 1)

    overall = round(sum(scores.values()) / len(scores), 1)

    return SecurityPosture(
        overall=overall,
        prompt_security=scores.get("prompt_security", 100.0),
        credential_protection=scores.get("credential_protection", 100.0),
        source_protection=scores.get("source_protection", 100.0),
        response_protection=scores.get("response_protection", 100.0),
        memory_protection=scores.get("memory_protection", 100.0),
    )


def _compute_threat_trends(db: Session) -> list[dict]:
    """Daily threat counts for the last 7 days."""
    trends = []
    now = datetime.now(timezone.utc)
    for i in range(6, -1, -1):
        day = now - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        total = db.query(func.count(Incident.id)).filter(
            Incident.timestamp >= start,
            Incident.timestamp < end,
        ).scalar() or 0
        blocked = db.query(func.count(Incident.id)).filter(
            Incident.timestamp >= start,
            Incident.timestamp < end,
            Incident.decision == "BLOCK",
        ).scalar() or 0
        trends.append({
            "date": start.strftime("%b %d"),
            "total": total,
            "blocked": blocked,
            "safe": total - blocked,
        })
    return trends


def _compute_category_distribution(db: Session) -> list[dict]:
    """Threat category counts."""
    results = (
        db.query(Incident.threat_category, func.count(Incident.id))
        .filter(Incident.threat_category != "Safe")
        .group_by(Incident.threat_category)
        .all()
    )
    return [{"category": cat, "count": count} for cat, count in results]
