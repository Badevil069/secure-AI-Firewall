"""Policies & Profiles endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from config import settings
from schemas import PoliciesResponse, PolicyOut, PolicyUpdate, AgentProfileOut
from security import policy_engine
from security.decision_engine import FIREWALL_MODES

router = APIRouter()

# ── Agent Profiles ─────────────────────────────────────────────────

AGENT_PROFILES = [
    {
        "id": 1, "name": "Developer Assistant", "slug": "developer",
        "description": "AI assistant for software development tasks",
        "allowed_topics": ["Code explanation", "Debugging", "Architecture", "Best practices", "Documentation"],
        "blocked_topics": [".env files", "Secrets", "Repository access", "Production credentials", "Internal APIs"],
        "policies": ["prompt_injection_protection", "credential_protection", "source_code_protection"],
    },
    {
        "id": 2, "name": "Customer Support", "slug": "customer_support",
        "description": "Customer-facing support agent",
        "allowed_topics": ["Product info", "Order status", "Returns", "FAQ", "Account help"],
        "blocked_topics": ["Other customers' data", "Internal pricing", "Employee info", "System access", "Database queries"],
        "policies": ["prompt_injection_protection", "data_exfiltration_protection", "credential_protection"],
    },
    {
        "id": 3, "name": "Finance Bot", "slug": "finance",
        "description": "Financial analysis and reporting assistant",
        "allowed_topics": ["Market trends", "Financial concepts", "Budgeting", "Calculations", "Reporting templates"],
        "blocked_topics": ["Actual financials", "Revenue data", "Salary info", "Bank credentials", "Tax records"],
        "policies": ["prompt_injection_protection", "data_exfiltration_protection", "credential_protection"],
    },
    {
        "id": 4, "name": "HR Assistant", "slug": "hr",
        "description": "Human resources policy and benefits assistant",
        "allowed_topics": ["Leave policy", "Benefits info", "Onboarding", "Company culture", "General HR FAQ"],
        "blocked_topics": ["Salary data", "Employee records", "Performance reviews", "Disciplinary actions", "Personal details"],
        "policies": ["prompt_injection_protection", "data_exfiltration_protection", "memory_protection"],
    },
    {
        "id": 5, "name": "Custom AI", "slug": "custom",
        "description": "General purpose AI with all protections enabled",
        "allowed_topics": ["General knowledge", "Conversation", "Analysis", "Writing", "Research"],
        "blocked_topics": ["System internals", "Credentials", "Source code", "Private data"],
        "policies": ["prompt_injection_protection", "jailbreak_protection", "credential_protection",
                      "source_code_protection", "data_exfiltration_protection", "response_sanitization", "memory_protection"],
    },
]


@router.get("/api/policies", response_model=PoliciesResponse)
async def get_policies():
    """Return all firewall policies with current state."""
    policies_data = policy_engine.get_policies()
    return PoliciesResponse(
        policies=[
            PolicyOut(
                id=i + 1,
                name=p["name"],
                slug=p["slug"],
                description=p["description"],
                enabled=p["enabled"],
                blocked_count=0,
                last_triggered=None,
            )
            for i, p in enumerate(policies_data)
        ],
        risk_threshold=settings.RISK_THRESHOLD,
        firewall_mode=settings.DEFAULT_FIREWALL_MODE,
    )


@router.put("/api/policies/{slug}")
async def update_policy(slug: str, update: PolicyUpdate):
    """Toggle a policy on/off."""
    success = policy_engine.set_policy_state(slug, update.enabled)
    if not success:
        return {"error": "Policy not found"}
    return {"success": True, "slug": slug, "enabled": update.enabled}


@router.get("/api/profiles", response_model=list[AgentProfileOut])
async def get_profiles():
    """Return all AI agent profiles."""
    return [
        AgentProfileOut(
            id=p["id"],
            name=p["name"],
            slug=p["slug"],
            description=p["description"],
            allowed_topics=p["allowed_topics"],
            blocked_topics=p["blocked_topics"],
            policies=p["policies"],
        )
        for p in AGENT_PROFILES
    ]


@router.get("/api/firewall-modes")
async def get_firewall_modes():
    """Return available firewall modes."""
    return {
        mode: {"name": mode.title(), "description": info["description"]}
        for mode, info in FIREWALL_MODES.items()
    }
