"""Security.AI — SQLAlchemy models."""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    session_id = Column(String(64), nullable=True, index=True)
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=True)
    attack_id = Column(String(32), nullable=True)
    threat_category = Column(String(64), nullable=False, default="Safe")
    technique = Column(String(128), nullable=True)
    severity = Column(String(16), nullable=False, default="None")
    risk_score = Column(Integer, nullable=False, default=0)
    trust_score = Column(Integer, nullable=False, default=100)
    confidence = Column(Float, nullable=False, default=0.0)
    decision = Column(String(16), nullable=False, default="ALLOW")
    reason = Column(Text, nullable=True)
    matched_pattern = Column(Text, nullable=True)
    policy_triggered = Column(String(128), nullable=True)
    agent_profile = Column(String(64), nullable=True)
    firewall_mode = Column(String(16), nullable=True)
    pipeline_results = Column(JSON, nullable=True)
    redactions_applied = Column(JSON, nullable=True)


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    slug = Column(String(64), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    blocked_count = Column(Integer, default=0, nullable=False)
    last_triggered = Column(DateTime, nullable=True)


class AgentProfile(Base):
    __tablename__ = "agent_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    slug = Column(String(64), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    allowed_topics = Column(JSON, nullable=True)
    blocked_topics = Column(JSON, nullable=True)
    policies = Column(JSON, nullable=True)


class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(64), unique=True, nullable=False)
    value = Column(Text, nullable=True)
