"""Incidents endpoint — Search and filter security incidents."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
import math

from database import get_db
from models import Incident
from schemas import IncidentListResponse, IncidentOut

router = APIRouter()


@router.get("/api/incidents", response_model=IncidentListResponse)
async def get_incidents(
    category: str = Query(None, description="Filter by threat category"),
    severity: str = Query(None, description="Filter by severity"),
    decision: str = Query(None, description="Filter by decision"),
    search: str = Query(None, description="Search in prompt text"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Return paginated, filtered incidents."""
    query = db.query(Incident)

    if category:
        query = query.filter(Incident.threat_category == category)
    if severity:
        query = query.filter(Incident.severity == severity)
    if decision:
        query = query.filter(Incident.decision == decision)
    if search:
        query = query.filter(Incident.prompt.ilike(f"%{search}%"))

    total = query.count()
    pages = max(1, math.ceil(total / limit))

    incidents = (
        query.order_by(desc(Incident.timestamp))
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return IncidentListResponse(
        incidents=[
            IncidentOut(
                id=i.id,
                timestamp=i.timestamp.isoformat() if i.timestamp else "",
                prompt=i.prompt,
                response=i.response,
                attack_id=i.attack_id,
                threat_category=i.threat_category,
                technique=i.technique,
                severity=i.severity,
                risk_score=i.risk_score,
                trust_score=i.trust_score,
                confidence=i.confidence,
                decision=i.decision,
                reason=i.reason,
                matched_pattern=i.matched_pattern,
                policy_triggered=i.policy_triggered,
                agent_profile=i.agent_profile,
                firewall_mode=i.firewall_mode,
                pipeline_results=i.pipeline_results,
                redactions_applied=i.redactions_applied,
            )
            for i in incidents
        ],
        total=total,
        page=page,
        pages=pages,
    )
