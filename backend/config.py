"""Security.AI — Configuration."""

import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    APP_NAME: str = "Security.AI"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Zero-Trust AI Firewall for Enterprise AI Agents"

    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./security_ai.db")

    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    DEMO_MODE: bool = os.getenv("DEMO_MODE", "true").lower() == "true"

    RISK_THRESHOLD: int = int(os.getenv("RISK_THRESHOLD", "75"))
    DEFAULT_FIREWALL_MODE: str = os.getenv("DEFAULT_FIREWALL_MODE", "balanced")

    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()
