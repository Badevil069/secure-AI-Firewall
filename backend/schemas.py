"""Security.AI — Pydantic schemas."""

from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, Field


# ── Detection & Analysis ──────────────────────────────────────────────

class DetectionResult(BaseModel):
    detector: str = ""
    detected: bool = False
    category: str = "Safe"
    technique: str = ""
    confidence: float = 0.0
    matched_pattern: str = ""
    reason: str = ""


class PipelineStep(BaseModel):
    name: str
    status: str  # "passed" | "detected" | "skipped"
    detail: str = ""


class ThreatAnalysis(BaseModel):
    attack_id: str | None = None
    category: str = "Safe"
    technique: str = ""
    severity: str = "None"  # None | Low | Medium | High | Critical
    risk_score: int = 0
    trust_score: int = 100
    confidence: float = 0.0
    decision: str = "ALLOW"  # ALLOW | WARN | BLOCK
    reason: str = ""
    explanation: str = ""
    matched_pattern: str = ""
    policy_triggered: str = ""
    pipeline: list[PipelineStep] = []


class RedactionInfo(BaseModel):
    type: str  # "API Key" | "Password" | "Token" | "PII" | "Source Code"
    action: str = "Redacted"
    reason: str = ""
    original_snippet: str = ""
    redacted_snippet: str = ""


# ── Request / Response ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4096)
    session_id: str = "default"
    agent_profile: str = "developer"
    firewall_mode: str = "balanced"


class AnalyzeResponse(BaseModel):
    threat_analysis: ThreatAnalysis
    timestamp: str = ""


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4096)
    session_id: str = "default"
    conversation_id: str = ""
    agent_profile: str = "developer"
    firewall_mode: str = "balanced"


class ChatResponse(BaseModel):
    response: str = ""
    was_blocked: bool = False
    threat_analysis: ThreatAnalysis
    redactions: list[RedactionInfo] = []
    timestamp: str = ""


# ── Dashboard ─────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_requests: int = 0
    safe_requests: int = 0
    blocked_threats: int = 0
    warned_requests: int = 0
    critical_threats: int = 0
    security_score: float = 100.0
    session_risk: float = 0.0


class SecurityPosture(BaseModel):
    overall: float = 100.0
    prompt_security: float = 100.0
    credential_protection: float = 100.0
    source_protection: float = 100.0
    response_protection: float = 100.0
    memory_protection: float = 100.0


class TimelineEvent(BaseModel):
    timestamp: str
    category: str
    decision: str
    risk_score: int
    attack_id: str | None = None


class DashboardResponse(BaseModel):
    stats: DashboardStats
    posture: SecurityPosture
    timeline: list[TimelineEvent] = []
    threat_trends: list[dict] = []
    category_distribution: list[dict] = []


# ── Incidents ─────────────────────────────────────────────────────────

class IncidentOut(BaseModel):
    id: int
    timestamp: str
    prompt: str
    response: str | None = None
    attack_id: str | None = None
    threat_category: str
    technique: str | None = None
    severity: str
    risk_score: int
    trust_score: int
    confidence: float
    decision: str
    reason: str | None = None
    matched_pattern: str | None = None
    policy_triggered: str | None = None
    agent_profile: str | None = None
    firewall_mode: str | None = None
    pipeline_results: list[dict] | None = None
    redactions_applied: list[dict] | None = None


class IncidentListResponse(BaseModel):
    incidents: list[IncidentOut]
    total: int
    page: int
    pages: int


# ── Policies ──────────────────────────────────────────────────────────

class PolicyOut(BaseModel):
    id: int
    name: str
    slug: str
    description: str | None
    enabled: bool
    blocked_count: int
    last_triggered: str | None


class PolicyUpdate(BaseModel):
    enabled: bool


class PoliciesResponse(BaseModel):
    policies: list[PolicyOut]
    risk_threshold: int
    firewall_mode: str


# ── Agent Profiles ────────────────────────────────────────────────────

class AgentProfileOut(BaseModel):
    id: int
    name: str
    slug: str
    description: str | None
    allowed_topics: list[str] | None
    blocked_topics: list[str] | None
    policies: list[str] | None
