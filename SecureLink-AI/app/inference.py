"""
SecureLink AI — Inference Orchestrator

This is the main entry point for analyzing a URL. It coordinates:
  1. Cache check (instant return if URL scanned recently)
  2. Feature extraction (URL structure + WHOIS + SSL)
  3. Parallel async threat intel API calls
  4. ML model prediction
  5. SHAP + rule-based explainability
  6. Weighted score computation (fixed weights, documented below)
  7. Persistence to database

Scoring weights (FIXED — not learned from live API data, which is
infeasible on free-tier rate limits of 4 req/min / 500 req/day):
  ML model:         50% — calibrated XGBoost on URL+domain features
  VirusTotal:       25% — high-confidence vendor detections
  Google Safe Brws: 15% — Google's threat list (fast binary signal)
  Rule engine:      10% — deterministic heuristics (IP, young domain, etc.)

Rationale: ML gets the most weight because it has seen training examples.
VT gets the second-most because professional security teams curate it.
Safe Browsing is fast but binary. Rules are a last-resort sanity check.

Future improvement: train a logistic regression meta-model offline on a
manually-cached sample of 100–200 URLs with real VT/SB labels (see
app/meta_model.py stub). The fixed weights are a defensible baseline.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

from app.config import get_settings
from app.database import save_scan
from app.explainability import (
    compute_shap_reasons,
    get_rule_based_reasons,
    merge_reasons,
)
from app.feature_engineering import URLFeatures, extract_features
from app.model import get_metadata, is_synthetic_model, predict
from app.openphish import check_openphish
from app.phishtank import check_phishtank
from app.report_generator import generate_report
from app.safebrowsing import check_safe_browsing
from app.urlscan_api import check_urlscan
from app.utils import clamp, hash_url, normalize_url, recommendation, risk_band
from app.vt_api import check_virustotal

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Complete result of a URL security analysis."""

    url: str
    normalized_url: str
    risk_score: int                    # 0–100 (higher = more dangerous)
    trust_score: int                   # 100 - risk_score (for user display)
    prediction: str                    # Risk band label
    confidence: float                  # ML calibrated probability (0.0–1.0)
    reasons: list[str] = field(default_factory=list)  # Top 5 human-readable reasons
    recommendation_text: str = ""
    is_synthetic_model: bool = False
    scan_id: Optional[int] = None
    # Component scores (for transparency)
    ml_probability: float = 0.0
    vt_detection_ratio: float = 0.0
    sb_flagged: bool = False
    rule_score: float = 0.0
    # API availability flags
    vt_available: bool = False
    sb_available: bool = False
    urlscan_available: bool = False
    # Formatted report for Telegram
    formatted_report: str = ""


async def analyze_url(url: str, user_id: str = "api") -> AnalysisResult:
    """
    Full async analysis pipeline for a single URL.

    Args:
        url: The URL to analyze (must be validated before calling this).
        user_id: Telegram user ID or "api" for direct API calls.

    Returns:
        AnalysisResult with the complete analysis.
    """
    settings = get_settings()
    normalized = normalize_url(url)

    logger.info("Analyzing URL: %s | user=%s", normalized, user_id)

    # ── Step 1: Feature extraction ────────────────────────────────────────────
    features = await extract_features(normalized, include_network=True)

    # ── Step 2: ML prediction ─────────────────────────────────────────────────
    ml_prob, ml_label = predict(features)

    # ── Step 3: Parallel threat intel API calls ───────────────────────────────
    # All 4 API calls run concurrently — not sequentially — to keep response
    # time low. Each has its own timeout and cache check.
    vt_result, sb_result, urlscan_result, openphish_flagged, phishtank_result = (
        await asyncio.gather(
            check_virustotal(normalized),
            check_safe_browsing(normalized),
            check_urlscan(normalized),
            check_openphish(normalized),
            check_phishtank(normalized),
            return_exceptions=True,
        )
    )

    # Handle any exceptions from gather (replace with safe defaults)
    from app.vt_api import VTResult
    from app.safebrowsing import SafeBrowsingResult
    from app.urlscan_api import URLScanResult
    from app.phishtank import PhishTankResult

    if isinstance(vt_result, Exception):
        logger.warning("VT gather exception: %s", vt_result)
        vt_result = VTResult(available=False)
    if isinstance(sb_result, Exception):
        logger.warning("SB gather exception: %s", sb_result)
        sb_result = SafeBrowsingResult(available=False)
    if isinstance(urlscan_result, Exception):
        urlscan_result = URLScanResult(available=False)
    if isinstance(openphish_flagged, Exception):
        openphish_flagged = False
    if isinstance(phishtank_result, Exception):
        phishtank_result = PhishTankResult(available=False)

    # ── Step 4: Compute rule-based score (0.0–1.0) ────────────────────────────
    rule_score = _compute_rule_score(
        features, openphish_flagged, phishtank_result
    )

    # ── Step 5: Weighted final risk score (0–100) ─────────────────────────────
    # Fixed weights — see module docstring for rationale.
    w = settings  # access weight constants
    vt_ratio = vt_result.detection_ratio if vt_result.available else 0.0
    sb_flag = 1.0 if (sb_result.available and sb_result.is_flagged) else 0.0

    raw_score = (
        w.weight_ml * ml_prob
        + w.weight_vt * vt_ratio
        + w.weight_sb * sb_flag
        + w.weight_rule * rule_score
    )
    risk_score = int(clamp(raw_score, 0.0, 1.0) * 100)

    # ── Step 6: Explainability ────────────────────────────────────────────────
    import pandas as pd
    from app.model import _model  # type: ignore[attr-defined]

    features_df = pd.DataFrame([features.to_dict()])
    shap_reasons = []

    if _model is not None:
        shap_reasons = compute_shap_reasons(_model, features_df, top_n=5)

    rule_reasons = get_rule_based_reasons(features, vt_result, sb_result)
    reasons = merge_reasons(shap_reasons, rule_reasons, max_total=5)

    # ── Step 7: Build result ──────────────────────────────────────────────────
    prediction_label = risk_band(risk_score)
    rec_text = recommendation(risk_score)
    synthetic = is_synthetic_model()

    result = AnalysisResult(
        url=url,
        normalized_url=normalized,
        risk_score=risk_score,
        trust_score=100 - risk_score,
        prediction=prediction_label,
        confidence=round(ml_prob, 4),
        reasons=reasons,
        recommendation_text=rec_text,
        is_synthetic_model=synthetic,
        ml_probability=round(ml_prob, 4),
        vt_detection_ratio=round(vt_ratio, 4),
        sb_flagged=bool(sb_flag),
        rule_score=round(rule_score, 4),
        vt_available=vt_result.available,
        sb_available=sb_result.available,
        urlscan_available=urlscan_result.available,
    )

    # ── Step 8: Format report ─────────────────────────────────────────────────
    result.formatted_report = generate_report(result)

    # ── Step 9: Persist to database (malicious only) ──────────────────────────
    # Privacy policy: only URLs flagged as Suspicious / Dangerous / Critical
    # (risk_score >= 41) are stored. Safe and Moderate Risk scans are discarded
    # immediately — no URL history is kept for clean links.
    STORE_THRESHOLD = 41

    if risk_score >= STORE_THRESHOLD:
        api_results = {
            "virustotal": {
                "available": vt_result.available,
                "malicious": vt_result.malicious_count,
                "total": vt_result.total_engines,
            },
            "safe_browsing": {
                "available": sb_result.available,
                "flagged": sb_result.is_flagged,
            },
            "openphish": {"flagged": openphish_flagged},
            "phishtank": {
                "available": phishtank_result.available,
                "is_phishing": phishtank_result.is_phishing,
            },
        }
        try:
            scan_id = save_scan(
                user_id=user_id,
                url=normalized,
                prediction=prediction_label,
                confidence=round(ml_prob, 4),
                risk_score=risk_score,
                api_results=api_results,
                shap_reasons=[r.replace("• ", "") for r in reasons],
                is_synthetic_model=synthetic,
            )
            result.scan_id = scan_id
        except Exception as exc:
            logger.warning("Failed to save scan to database: %s", exc)
    else:
        logger.debug("URL scored %d (< %d) — not stored (privacy policy).", risk_score, STORE_THRESHOLD)

    logger.info(
        "Analysis complete | score=%d | prediction=%s | vt_available=%s | sb_available=%s",
        risk_score,
        prediction_label,
        vt_result.available,
        sb_result.available,
    )

    return result


def _compute_rule_score(features: URLFeatures, openphish_flagged: bool, phishtank_result) -> float:
    """
    Deterministic rule-based score (0.0–1.0).
    Each rule contributes a fixed amount; total is normalized to [0, 1].
    """
    score = 0.0

    if features.has_ip_address:
        score += 0.25
    if features.is_shortened_url:
        score += 0.15
    if features.has_https == 0:
        score += 0.15
    if 0 <= features.domain_age_days < 7:
        score += 0.30
    elif 7 <= features.domain_age_days < 30:
        score += 0.20
    if features.suspicious_keyword_count >= 2:
        score += 0.15
    if features.url_entropy > 4.5:
        score += 0.10
    if features.ssl_is_self_signed == 1:
        score += 0.15
    if features.ssl_is_valid == 0:
        score += 0.10
    if openphish_flagged:
        score += 0.40
    if phishtank_result and phishtank_result.available and phishtank_result.is_phishing:
        score += 0.40

    return clamp(score, 0.0, 1.0)
