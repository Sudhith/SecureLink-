"""
SecureLink AI — FastAPI Application

Endpoints:
  POST /scan            — Analyze a URL (used by dashboard + direct API consumers)
  POST /telegram/webhook — Receives Telegram updates in production webhook mode
  GET  /health          — Health check (deployment readiness probe)
  GET  /history         — Recent scans (paginated)
  GET  /stats           — Aggregate statistics

The Telegram bot application is started/stopped via FastAPI's lifespan context.
APScheduler runs periodic cleanup tasks (cache + data retention).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl

from app.config import configure_logging, get_settings
from app.database import cleanup_expired_cache, create_tables, get_all_scans, get_global_stats, purge_old_scans
from app.inference import analyze_url
from app.model import get_metadata, load_model
from app.utils import is_valid_url

logger = logging.getLogger(__name__)


# ── Pydantic models for API ───────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    user_id: str = "api"


class ScanResponse(BaseModel):
    url: str
    risk_score: int
    prediction: str
    confidence: float
    reasons: list[str]
    recommendation: str
    vt_available: bool
    sb_available: bool
    is_synthetic_model: bool
    scan_id: Optional[int] = None


# ── Lifespan (startup + shutdown) ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan — runs on startup and shutdown.
    Starts the Telegram bot, loads the model, sets up scheduler.
    """
    configure_logging()
    settings = get_settings()

    # ── Database ──────────────────────────────────────────────────────────────
    create_tables()
    logger.info("Database initialized at %s", settings.database_path)

    # Warn if DB is not on a persistent volume in production
    import os
    db_path = settings.database_path
    if settings.is_production and not db_path.startswith("/data"):
        logger.warning(
            "Production mode detected but DATABASE_PATH=%s does not start with /data. "
            "Scan history may be lost on redeploy. "
            "Set DATABASE_PATH=/data/securelink.db and mount a Railway Volume to /data.",
            db_path,
        )

    # ── Model ─────────────────────────────────────────────────────────────────
    loaded = load_model(settings.model_path)
    if not loaded:
        logger.warning(
            "No model found — running without ML predictions. "
            "Run: python scripts/train_model.py"
        )

    # ── APScheduler: periodic cleanup ─────────────────────────────────────────
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    scheduler = AsyncIOScheduler()
    scheduler.add_job(cleanup_expired_cache, "interval", hours=6, id="cache_cleanup")
    scheduler.add_job(
        lambda: purge_old_scans(retention_days=30),
        "interval",
        hours=24,
        id="data_retention",
    )
    scheduler.start()
    logger.info("APScheduler started (cache cleanup every 6h, data retention every 24h).")

    # ── Telegram bot ──────────────────────────────────────────────────────────
    bot_app = None
    if settings.telegram_bot_token:
        try:
            from bot.telegram_bot import build_application
            bot_app = build_application()

            if settings.is_production:
                # Webhook mode: Telegram POSTs updates to /telegram/webhook
                await bot_app.initialize()
                await bot_app.start()
                webhook_url = f"{settings.webhook_url.rstrip('/')}/telegram/webhook"
                await bot_app.bot.set_webhook(webhook_url)
                logger.info("Telegram webhook set: %s", webhook_url)
            else:
                # Polling mode for local development
                await bot_app.initialize()
                await bot_app.start()
                await bot_app.updater.start_polling()
                logger.info("Telegram bot started in polling mode.")

            # Store in app state for webhook endpoint
            app.state.bot_app = bot_app
        except Exception as exc:
            logger.error("Failed to start Telegram bot: %s", exc)
    else:
        logger.warning("TELEGRAM_BOT_TOKEN not set — bot disabled.")
        app.state.bot_app = None

    logger.info("SecureLink AI startup complete.")
    yield  # Application runs

    # ── Shutdown ──────────────────────────────────────────────────────────────
    scheduler.shutdown(wait=False)
    if bot_app:
        try:
            await bot_app.updater.stop()
            await bot_app.stop()
            await bot_app.shutdown()
        except Exception:
            pass
    logger.info("SecureLink AI shutdown complete.")


# ── App instance ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="SecureLink AI",
    description="ML-powered URL security analyzer",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Meta"])
async def health_check():
    """Deployment health check — returns model and bot status."""
    settings = get_settings()
    metadata = get_metadata()
    return {
        "status": "ok",
        "model_loaded": bool(metadata),
        "is_synthetic_model": metadata.get("is_synthetic", True),
        "bot_token_configured": bool(settings.telegram_bot_token),
        "mode": "webhook" if settings.is_production else "polling",
    }


@app.post("/scan", response_model=ScanResponse, tags=["Analysis"])
async def scan_url(request: ScanRequest):
    """Analyze a URL and return a full security report."""
    url = request.url.strip()

    if not is_valid_url(url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid URL format. Must be a valid http:// or https:// URL.",
        )

    try:
        result = await analyze_url(url, user_id=request.user_id)
    except Exception as exc:
        logger.exception("Analysis failed for URL %s: %s", url, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed. Please try again.",
        )

    return ScanResponse(
        url=result.normalized_url,
        risk_score=result.risk_score,
        prediction=result.prediction,
        confidence=result.confidence,
        reasons=result.reasons,
        recommendation=result.recommendation_text,
        vt_available=result.vt_available,
        sb_available=result.sb_available,
        is_synthetic_model=result.is_synthetic_model,
        scan_id=result.scan_id,
    )


@app.post("/telegram/webhook", tags=["Bot"], include_in_schema=False)
async def telegram_webhook(request: Request):
    """Receive Telegram updates in production webhook mode."""
    bot_app = getattr(request.app.state, "bot_app", None)
    if not bot_app:
        return JSONResponse({"status": "bot not configured"}, status_code=200)

    try:
        from telegram import Update
        data = await request.json()
        update = Update.de_json(data, bot_app.bot)
        await bot_app.process_update(update)
    except Exception as exc:
        logger.error("Webhook processing error: %s", exc)

    # Always return 200 to Telegram (otherwise it retries)
    return JSONResponse({"status": "ok"})


@app.get("/history", tags=["Data"])
async def get_history(limit: int = 50):
    """Return recent scan history (for dashboard)."""
    scans = get_all_scans(limit=min(limit, 500))
    return {
        "scans": [
            {
                "id": s.id,
                "url": s.url,
                "prediction": s.prediction,
                "risk_score": s.risk_score,
                "confidence": s.confidence,
                "timestamp": s.timestamp.isoformat(),
                "user_id": s.user_id,
            }
            for s in scans
        ]
    }


@app.get("/stats", tags=["Data"])
async def get_stats():
    """Return aggregate statistics."""
    return get_global_stats()
