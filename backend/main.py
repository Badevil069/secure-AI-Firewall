"""Security.AI — FastAPI Application Entry Point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from database import init_db
from routers import analyze, chat, dashboard, incidents, policies


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(analyze.router, tags=["Analyze"])
app.include_router(chat.router, tags=["Chat"])
app.include_router(dashboard.router, tags=["Dashboard"])
app.include_router(incidents.router, tags=["Incidents"])
app.include_router(policies.router, tags=["Policies"])


@app.get("/api/health")
async def health_check():
    return {
        "status": "operational",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "demo_mode": settings.DEMO_MODE,
        "ai_configured": bool(settings.GEMINI_API_KEY),
    }
