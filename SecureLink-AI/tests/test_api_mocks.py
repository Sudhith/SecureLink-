"""
Tests for API client modules: vt_api.py, safebrowsing.py, phishtank.py

All external HTTP calls are mocked with pytest-mock / unittest.mock.
Tests run fully offline and are not rate-limited.

Run: pytest tests/test_api_mocks.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock


# ── VirusTotal ────────────────────────────────────────────────────────────────

class TestVirusTotal:
    @pytest.mark.asyncio
    async def test_returns_unavailable_without_key(self):
        """VT client returns VTResult(available=False) when API key is absent."""
        with patch("app.vt_api.get_settings") as mock_settings:
            mock_settings.return_value.has_virustotal = False
            from app.vt_api import check_virustotal
            result = await check_virustotal("https://example.com")
        assert result.available is False

    @pytest.mark.asyncio
    async def test_cache_hit_skips_http_call(self):
        """When cache contains a result, no HTTP call should be made."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5, "suspicious": 1,
                        "harmless": 70, "undetected": 4,
                    }
                }
            }
        }

        with (
            patch("app.vt_api.get_settings") as mock_settings,
            patch("app.vt_api.get_cache", return_value=mock_cache),
        ):
            mock_settings.return_value.has_virustotal = True
            mock_settings.return_value.virustotal_api_key = "test_key"

            from app.vt_api import check_virustotal
            result = await check_virustotal("https://example.com")

        assert result.available is True
        assert result.malicious_count == 5
        mock_cache.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_api_error_returns_unavailable(self):
        """HTTP errors should return VTResult(available=False) gracefully."""
        mock_cache = MagicMock()
        mock_cache.get.return_value = None  # Cache miss

        with (
            patch("app.vt_api.get_settings") as mock_settings,
            patch("app.vt_api.get_cache", return_value=mock_cache),
            patch("app.vt_api._call_virustotal_api", new=AsyncMock(side_effect=Exception("Timeout"))),
        ):
            mock_settings.return_value.has_virustotal = True
            mock_settings.return_value.virustotal_api_key = "test_key"

            from app.vt_api import check_virustotal
            result = await check_virustotal("https://example.com")

        assert result.available is False

    def test_parse_vt_response_malicious(self):
        """Parse a realistic VT API response."""
        from app.vt_api import _parse_vt_response
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 2,
                        "harmless": 60,
                        "undetected": 8,
                    },
                    "categories": {"engine1": "phishing", "engine2": "malware"},
                }
            }
        }
        result = _parse_vt_response(data)
        assert result.available is True
        assert result.malicious_count == 10
        assert result.total_engines == 80
        assert pytest.approx(result.detection_ratio, abs=0.001) == 10 / 80

    def test_parse_vt_response_clean(self):
        """Parse a clean VT response."""
        from app.vt_api import _parse_vt_response
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0,
                        "harmless": 90, "undetected": 5,
                    }
                }
            }
        }
        result = _parse_vt_response(data)
        assert result.available is True
        assert result.detection_ratio == 0.0


# ── Google Safe Browsing ──────────────────────────────────────────────────────

class TestSafeBrowsing:
    @pytest.mark.asyncio
    async def test_returns_unavailable_without_key(self):
        with patch("app.safebrowsing.get_settings") as mock_settings:
            mock_settings.return_value.has_safe_browsing = False
            from app.safebrowsing import check_safe_browsing
            result = await check_safe_browsing("https://example.com")
        assert result.available is False

    def test_parse_flagged_response(self):
        """Parse a response where the URL is flagged."""
        from app.safebrowsing import _parse_sb_response
        data = {
            "matches": [
                {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM"},
                {"threatType": "MALWARE", "platformType": "ANY_PLATFORM"},
            ]
        }
        result = _parse_sb_response(data)
        assert result.available is True
        assert result.is_flagged is True
        assert "SOCIAL_ENGINEERING" in result.threat_types

    def test_parse_clean_response(self):
        """Parse a response with no matches (clean URL)."""
        from app.safebrowsing import _parse_sb_response
        data = {}  # Empty dict = no matches key = clean
        result = _parse_sb_response(data)
        assert result.available is True
        assert result.is_flagged is False

    @pytest.mark.asyncio
    async def test_cache_hit_skips_http_call(self):
        """Cache hit should bypass the HTTP call."""
        cached_response = {}  # clean URL response
        mock_cache = MagicMock()
        mock_cache.get.return_value = cached_response

        with (
            patch("app.safebrowsing.get_settings") as mock_settings,
            patch("app.safebrowsing.get_cache", return_value=mock_cache),
        ):
            mock_settings.return_value.has_safe_browsing = True
            mock_settings.return_value.google_safe_browsing_key = "test_key"

            from app.safebrowsing import check_safe_browsing
            result = await check_safe_browsing("https://example.com")

        assert result.available is True
        mock_cache.get.assert_called_once()


# ── PhishTank ─────────────────────────────────────────────────────────────────

class TestPhishTank:
    @pytest.mark.asyncio
    async def test_skipped_gracefully_without_key(self):
        """PhishTank is optional — skips without raising if key is absent."""
        with patch("app.phishtank.get_settings") as mock_settings:
            mock_settings.return_value.has_phishtank = False
            from app.phishtank import check_phishtank
            result = await check_phishtank("https://example.com")
        assert result.available is False
        # No exception should be raised

    def test_parse_phishing_response(self):
        from app.phishtank import _parse_phishtank_response
        data = {
            "results": {
                "in_database": True,
                "valid": True,
                "verified": True,
                "phish_detail_url": "https://phishtank.org/phish_detail.php?phish_id=123",
            }
        }
        result = _parse_phishtank_response(data)
        assert result.available is True
        assert result.is_phishing is True
        assert result.in_database is True

    def test_parse_not_in_database(self):
        from app.phishtank import _parse_phishtank_response
        data = {
            "results": {
                "in_database": False,
                "valid": False,
                "verified": False,
                "phish_detail_url": "",
            }
        }
        result = _parse_phishtank_response(data)
        assert result.available is True
        assert result.is_phishing is False


# ── Cache ─────────────────────────────────────────────────────────────────────

class TestCacheLayer:
    def test_cache_miss_returns_none(self, tmp_path, monkeypatch):
        """Cache miss should return None, not raise."""
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))

        # Re-import to pick up the new path
        import importlib
        import app.config as cfg
        cfg.get_settings.cache_clear()
        import app.database as db
        db._engine = None  # Reset engine
        db.create_tables()

        from app.cache import APICache
        cache = APICache(ttl_hours=1)
        result = cache.get("https://never-scanned.com", "virustotal")
        assert result is None

    def test_cache_roundtrip(self, tmp_path, monkeypatch):
        """Set and get should return the same data."""
        monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test2.db"))
        import app.config as cfg
        cfg.get_settings.cache_clear()
        import app.database as db
        db._engine = None
        db.create_tables()

        from app.cache import APICache
        cache = APICache(ttl_hours=1)
        url = "https://test-roundtrip.com"
        test_data = {"malicious": 5, "total": 80}

        cache.set(url, "virustotal", test_data)
        result = cache.get(url, "virustotal")
        assert result == test_data
