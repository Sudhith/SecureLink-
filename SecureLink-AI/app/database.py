"""
SecureLink AI — Database Models & CRUD Helpers

Uses SQLModel (SQLAlchemy + Pydantic hybrid) for type-safe ORM.
Three tables: scans, api_cache, feedback.

Data retention: scans older than RETENTION_DAYS are eligible for cleanup
(run via APScheduler periodic task). See api.py for the scheduler setup.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import create_engine, text
from sqlmodel import Field, Session, SQLModel, select

from app.config import get_settings

logger = logging.getLogger(__name__)

# ── Table Models ──────────────────────────────────────────────────────────────


class Scan(SQLModel, table=True):
    """Record of every URL scan performed."""

    __tablename__ = "scans"

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: str = Field(index=True)  # Telegram user ID (string for safety)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    url: str = Field(index=True)
    prediction: str  # "Safe" | "Moderate Risk" | "Suspicious" | "Dangerous" | "Critical"
    confidence: float  # 0.0–1.0 (calibrated probability)
    risk_score: int  # 0–100
    api_results: str = Field(default="{}")  # JSON string of raw API results
    shap_reasons: str = Field(default="[]")  # JSON string of top reasons
    is_synthetic_model: bool = Field(default=False)  # True when model trained on synthetic data


class APICache(SQLModel, table=True):
    """Cache for external API responses to respect free-tier rate limits."""

    __tablename__ = "api_cache"

    id: Optional[int] = Field(default=None, primary_key=True)
    url_hash: str = Field(index=True)  # SHA-256 of the URL
    api_name: str = Field(index=True)  # "virustotal" | "safebrowsing" | "urlscan" | etc.
    response: str  # JSON string of raw API response
    expires_at: datetime  # TTL expiry timestamp


class Feedback(SQLModel, table=True):
    """User feedback on scan predictions — forms the basis of a monitoring loop."""

    __tablename__ = "feedback"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id", index=True)
    user_id: str
    was_correct: bool  # True = user agrees; False = user thinks prediction is wrong
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    comment: Optional[str] = None  # Free-text comment (future feature)


# ── Engine & Session ──────────────────────────────────────────────────────────

_engine = None


def get_engine():
    """Return the SQLAlchemy engine (lazy singleton)."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.database_url,
            connect_args={"check_same_thread": False},
            echo=False,
        )
    return _engine


def create_tables() -> None:
    """Create all tables if they don't exist. Safe to call multiple times."""
    engine = get_engine()
    SQLModel.metadata.create_all(engine)
    logger.info("Database tables ensured.")


def get_session() -> Session:
    """Return a new database session. Caller is responsible for closing it."""
    return Session(get_engine())


# ── CRUD: Scans ───────────────────────────────────────────────────────────────


def save_scan(
    user_id: str,
    url: str,
    prediction: str,
    confidence: float,
    risk_score: int,
    api_results: dict,
    shap_reasons: list,
    is_synthetic_model: bool = False,
) -> int:
    """Persist a scan result and return its ID."""
    scan = Scan(
        user_id=user_id,
        url=url,
        prediction=prediction,
        confidence=confidence,
        risk_score=risk_score,
        api_results=json.dumps(api_results),
        shap_reasons=json.dumps(shap_reasons),
        is_synthetic_model=is_synthetic_model,
    )
    with get_session() as session:
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id  # type: ignore[return-value]


def get_user_history(user_id: str, limit: int = 10) -> list[Scan]:
    """Return the N most recent scans for a specific user."""
    with get_session() as session:
        statement = (
            select(Scan)
            .where(Scan.user_id == user_id)
            .order_by(Scan.timestamp.desc())  # type: ignore[attr-defined]
            .limit(limit)
        )
        return session.exec(statement).all()


def get_global_stats() -> dict:
    """Return aggregate scan statistics for the dashboard and /stats command."""
    with get_session() as session:
        result = session.exec(select(Scan)).all()
        if not result:
            return {"total_scans": 0, "avg_risk_score": 0, "flagged_count": 0}
        total = len(result)
        avg_risk = sum(s.risk_score for s in result) / total
        flagged = sum(1 for s in result if s.risk_score >= 66)
        return {
            "total_scans": total,
            "avg_risk_score": round(avg_risk, 1),
            "flagged_count": flagged,
        }


def get_all_scans(limit: int = 500) -> list[Scan]:
    """Return recent scans for the dashboard. Capped for performance."""
    with get_session() as session:
        statement = (
            select(Scan)
            .order_by(Scan.timestamp.desc())  # type: ignore[attr-defined]
            .limit(limit)
        )
        return session.exec(statement).all()


# ── CRUD: API Cache ───────────────────────────────────────────────────────────


def get_cached_api_response(url_hash: str, api_name: str) -> Optional[dict]:
    """Return a cached API response if it exists and hasn't expired."""
    now = datetime.now(timezone.utc)
    with get_session() as session:
        statement = select(APICache).where(
            APICache.url_hash == url_hash,
            APICache.api_name == api_name,
            APICache.expires_at > now,
        )
        row = session.exec(statement).first()
        if row:
            return json.loads(row.response)
    return None


def set_cached_api_response(
    url_hash: str,
    api_name: str,
    response: dict,
    expires_at: datetime,
) -> None:
    """Store or update a cached API response."""
    with get_session() as session:
        # Upsert: delete old entry if exists, then insert fresh
        old = session.exec(
            select(APICache).where(
                APICache.url_hash == url_hash,
                APICache.api_name == api_name,
            )
        ).first()
        if old:
            session.delete(old)
        entry = APICache(
            url_hash=url_hash,
            api_name=api_name,
            response=json.dumps(response),
            expires_at=expires_at,
        )
        session.add(entry)
        session.commit()


def cleanup_expired_cache() -> int:
    """Delete expired cache entries. Returns number of rows deleted."""
    now = datetime.now(timezone.utc)
    with get_session() as session:
        expired = session.exec(select(APICache).where(APICache.expires_at <= now)).all()
        count = len(expired)
        for row in expired:
            session.delete(row)
        session.commit()
    logger.info("Cache cleanup: removed %d expired entries.", count)
    return count


# ── CRUD: Feedback ────────────────────────────────────────────────────────────


def save_feedback(scan_id: int, user_id: str, was_correct: bool) -> None:
    """Record user feedback on a prediction."""
    with get_session() as session:
        # Avoid duplicate feedback from the same user for the same scan
        existing = session.exec(
            select(Feedback).where(
                Feedback.scan_id == scan_id,
                Feedback.user_id == user_id,
            )
        ).first()
        if existing:
            existing.was_correct = was_correct
            existing.timestamp = datetime.now(timezone.utc)
        else:
            fb = Feedback(scan_id=scan_id, user_id=user_id, was_correct=was_correct)
            session.add(fb)
        session.commit()


def get_all_feedback() -> list[Feedback]:
    """Return all feedback entries for the dashboard review panel."""
    with get_session() as session:
        return session.exec(select(Feedback).order_by(Feedback.timestamp.desc())).all()  # type: ignore[attr-defined]


def purge_old_scans(retention_days: int = 30) -> int:
    """Delete scans older than retention_days. Part of data retention policy."""
    from datetime import timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    with get_session() as session:
        old_scans = session.exec(select(Scan).where(Scan.timestamp < cutoff)).all()
        count = len(old_scans)
        for scan in old_scans:
            # Also delete associated feedback
            fbs = session.exec(select(Feedback).where(Feedback.scan_id == scan.id)).all()
            for fb in fbs:
                session.delete(fb)
            session.delete(scan)
        session.commit()
    logger.info("Data retention: purged %d scans older than %d days.", count, retention_days)
    return count
