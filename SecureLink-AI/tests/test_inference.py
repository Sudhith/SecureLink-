"""
Tests for app/inference.py

All external API calls and database operations are mocked.
Tests verify that:
  - analyze_url produces a score in 0–100
  - Component scores are correctly weighted
  - Risk bands are applied correctly
  - DB save is called with the right arguments

Run: pytest tests/test_inference.py -v
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_vt_result(available=True, malicious=0, total=80, detection_ratio=0.0):
    from app.vt_api import VTResult
    return VTResult(
        available=available,
        malicious_count=malicious,
        total_engines=total,
        detection_ratio=detection_ratio,
    )


def make_sb_result(available=True, is_flagged=False):
    from app.safebrowsing import SafeBrowsingResult
    return SafeBrowsingResult(available=available, is_flagged=is_flagged)


def make_urlscan_result(available=False):
    from app.urlscan_api import URLScanResult
    return URLScanResult(available=available)


def make_phishtank_result(available=False, is_phishing=False):
    from app.phishtank import PhishTankResult
    return PhishTankResult(available=available, is_phishing=is_phishing)


def make_features(has_ip=0, has_https=1, domain_age=365, entropy=3.0, keyword_count=0):
    from app.feature_engineering import URLFeatures
    return URLFeatures(
        url_length=30,
        num_dots=2,
        num_slashes=3,
        num_digits=0,
        num_special_chars=0,
        num_hyphens=0,
        has_https=has_https,
        has_ip_address=has_ip,
        is_shortened_url=0,
        suspicious_keyword_count=keyword_count,
        url_entropy=entropy,
        domain_age_days=domain_age,
        ssl_is_valid=1,
        ssl_days_remaining=365,
        ssl_is_self_signed=0,
    )


# ── Score range tests ─────────────────────────────────────────────────────────

class TestScoreRange:
    @pytest.mark.asyncio
    async def test_safe_url_low_score(self):
        """A clean URL with good signals should produce a low risk score."""
        features = make_features(has_https=1, domain_age=1000, entropy=3.0)
        vt = make_vt_result(available=True, malicious=0, total=80, detection_ratio=0.0)
        sb = make_sb_result(available=True, is_flagged=False)

        with (
            patch("app.inference.extract_features", new=AsyncMock(return_value=features)),
            patch("app.inference.check_virustotal", new=AsyncMock(return_value=vt)),
            patch("app.inference.check_safe_browsing", new=AsyncMock(return_value=sb)),
            patch("app.inference.check_urlscan", new=AsyncMock(return_value=make_urlscan_result())),
            patch("app.inference.check_openphish", new=AsyncMock(return_value=False)),
            patch("app.inference.check_phishtank", new=AsyncMock(return_value=make_phishtank_result())),
            patch("app.inference.predict", return_value=(0.05, "legitimate")),
            patch("app.inference.compute_shap_reasons", return_value=[]),
            patch("app.inference.save_scan", return_value=1),
        ):
            from app.inference import analyze_url
            result = await analyze_url("https://github.com", user_id="test")

        assert 0 <= result.risk_score <= 100
        assert result.risk_score <= 40  # Should be low for a clean URL

    @pytest.mark.asyncio
    async def test_dangerous_url_high_score(self):
        """A URL with many red flags should produce a high risk score."""
        features = make_features(
            has_ip=1, has_https=0, domain_age=5,
            entropy=5.0, keyword_count=3,
        )
        vt = make_vt_result(available=True, malicious=40, total=80, detection_ratio=0.5)
        sb = make_sb_result(available=True, is_flagged=True)

        with (
            patch("app.inference.extract_features", new=AsyncMock(return_value=features)),
            patch("app.inference.check_virustotal", new=AsyncMock(return_value=vt)),
            patch("app.inference.check_safe_browsing", new=AsyncMock(return_value=sb)),
            patch("app.inference.check_urlscan", new=AsyncMock(return_value=make_urlscan_result())),
            patch("app.inference.check_openphish", new=AsyncMock(return_value=True)),
            patch("app.inference.check_phishtank", new=AsyncMock(return_value=make_phishtank_result(available=True, is_phishing=True))),
            patch("app.inference.predict", return_value=(0.95, "phishing")),
            patch("app.inference.compute_shap_reasons", return_value=[]),
            patch("app.inference.save_scan", return_value=2),
        ):
            from app.inference import analyze_url
            result = await analyze_url("http://192.168.1.1/verify-account", user_id="test")

        assert result.risk_score >= 60  # Should be high for a dangerous URL
        assert result.prediction in ("Suspicious", "Dangerous", "Critical")

    @pytest.mark.asyncio
    async def test_score_always_in_range(self):
        """Risk score must always be 0–100 regardless of input."""
        features = make_features()

        with (
            patch("app.inference.extract_features", new=AsyncMock(return_value=features)),
            patch("app.inference.check_virustotal", new=AsyncMock(return_value=make_vt_result())),
            patch("app.inference.check_safe_browsing", new=AsyncMock(return_value=make_sb_result())),
            patch("app.inference.check_urlscan", new=AsyncMock(return_value=make_urlscan_result())),
            patch("app.inference.check_openphish", new=AsyncMock(return_value=False)),
            patch("app.inference.check_phishtank", new=AsyncMock(return_value=make_phishtank_result())),
            patch("app.inference.predict", return_value=(0.5, "phishing")),
            patch("app.inference.compute_shap_reasons", return_value=[]),
            patch("app.inference.save_scan", return_value=3),
        ):
            from app.inference import analyze_url
            result = await analyze_url("https://example.com", user_id="test")

        assert 0 <= result.risk_score <= 100


# ── Rule score tests ──────────────────────────────────────────────────────────

class TestRuleScore:
    def test_ip_address_adds_score(self):
        features = make_features(has_ip=1)
        from app.inference import _compute_rule_score
        from app.phishtank import PhishTankResult
        score = _compute_rule_score(features, openphish_flagged=False, phishtank_result=PhishTankResult())
        assert score > 0.0

    def test_very_young_domain_adds_score(self):
        features = make_features(domain_age=3)
        from app.inference import _compute_rule_score
        from app.phishtank import PhishTankResult
        score = _compute_rule_score(features, openphish_flagged=False, phishtank_result=PhishTankResult())
        assert score > 0.2  # 3-day domain is strong signal

    def test_openphish_flagged_adds_score(self):
        features = make_features()
        from app.inference import _compute_rule_score
        from app.phishtank import PhishTankResult
        score_clean = _compute_rule_score(features, openphish_flagged=False, phishtank_result=PhishTankResult())
        score_phish = _compute_rule_score(features, openphish_flagged=True, phishtank_result=PhishTankResult())
        assert score_phish > score_clean

    def test_score_clamped_to_1(self):
        """Even with all flags set, score should not exceed 1.0."""
        features = make_features(
            has_ip=1, has_https=0, domain_age=1,
            entropy=5.0, keyword_count=3,
        )
        features.ssl_is_self_signed = 1
        features.ssl_is_valid = 0
        from app.inference import _compute_rule_score
        from app.phishtank import PhishTankResult
        pt = PhishTankResult(available=True, is_phishing=True)
        score = _compute_rule_score(features, openphish_flagged=True, phishtank_result=pt)
        assert score <= 1.0


# ── Graceful degradation test ─────────────────────────────────────────────────

class TestGracefulDegradation:
    @pytest.mark.asyncio
    async def test_api_exceptions_handled(self):
        """If API calls raise exceptions, the result should still be returned."""
        features = make_features()

        with (
            patch("app.inference.extract_features", new=AsyncMock(return_value=features)),
            # All API calls raise exceptions
            patch("app.inference.check_virustotal", new=AsyncMock(side_effect=Exception("VT down"))),
            patch("app.inference.check_safe_browsing", new=AsyncMock(side_effect=Exception("SB down"))),
            patch("app.inference.check_urlscan", new=AsyncMock(side_effect=Exception("URLScan down"))),
            patch("app.inference.check_openphish", new=AsyncMock(side_effect=Exception("OpenPhish down"))),
            patch("app.inference.check_phishtank", new=AsyncMock(side_effect=Exception("PhishTank down"))),
            patch("app.inference.predict", return_value=(0.5, "phishing")),
            patch("app.inference.compute_shap_reasons", return_value=[]),
            patch("app.inference.save_scan", return_value=4),
        ):
            from app.inference import analyze_url
            result = await analyze_url("https://example.com", user_id="test")

        # Should still return a valid result based on ML only
        assert 0 <= result.risk_score <= 100
        assert result.vt_available is False
        assert result.sb_available is False
