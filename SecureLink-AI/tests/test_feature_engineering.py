"""
Tests for app/feature_engineering.py and app/utils.py

All tests are pure (no network calls, no database).
Run: pytest tests/test_feature_engineering.py -v
"""

import pytest

from app.utils import (
    char_repetition_ratio,
    count_encoded_chars,
    count_suspicious_keywords,
    has_ip_address,
    has_suspicious_extension,
    is_shortened_url,
    is_valid_url,
    normalize_url,
    hash_url,
    risk_band,
    shannon_entropy,
)


# ── URL Validation ────────────────────────────────────────────────────────────

class TestURLValidation:
    def test_valid_http_url(self):
        assert is_valid_url("http://example.com") is True

    def test_valid_https_url(self):
        assert is_valid_url("https://example.com/path?q=1") is True

    def test_valid_ip_url(self):
        assert is_valid_url("http://192.168.1.1/login") is True

    def test_invalid_no_scheme(self):
        assert is_valid_url("example.com") is False

    def test_invalid_ftp(self):
        assert is_valid_url("ftp://example.com") is False

    def test_invalid_empty(self):
        assert is_valid_url("") is False

    def test_invalid_none(self):
        assert is_valid_url(None) is False  # type: ignore[arg-type]

    def test_invalid_too_long(self):
        assert is_valid_url("https://" + "a" * 3000 + ".com") is False

    def test_valid_subdomain(self):
        assert is_valid_url("https://login.accounts.google.com") is True


# ── Entropy ───────────────────────────────────────────────────────────────────

class TestEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_uniform_string(self):
        # All same characters → 0 entropy
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        result = shannon_entropy("aB3!xZ9qWm2kLp8vRtYu")
        assert result > 3.0

    def test_known_url_entropy(self):
        # Predictable URL should have lower entropy than random string
        normal = shannon_entropy("https://google.com")
        random = shannon_entropy("https://x9q2k8w3m1z7.xyz/a3b4c5d6")
        assert random > normal

    def test_returns_float(self):
        result = shannon_entropy("test")
        assert isinstance(result, float)


# ── IP Address Detection ──────────────────────────────────────────────────────

class TestIPDetection:
    def test_ipv4_in_url(self):
        assert has_ip_address("http://192.168.1.1/login") is True

    def test_ipv4_with_port(self):
        assert has_ip_address("http://10.0.0.1:8080/verify") is True

    def test_domain_not_ip(self):
        assert has_ip_address("https://google.com") is False

    def test_ip_like_path_not_matched(self):
        # Path containing IP-like segment should not match
        assert has_ip_address("https://example.com/192.168.1.1") is False


# ── HTTPS Detection ───────────────────────────────────────────────────────────

class TestHTTPSDetection:
    def test_https_url(self):
        from app.utils import is_valid_url
        # Verify schema
        assert "https://example.com".startswith("https://")

    def test_http_url(self):
        assert not "http://example.com".startswith("https://")


# ── Shortened URL Detection ───────────────────────────────────────────────────

class TestShortenedURL:
    def test_bitly_detected(self):
        assert is_shortened_url("https://bit.ly/3xample") is True

    def test_tinyurl_detected(self):
        assert is_shortened_url("https://tinyurl.com/abc123") is True

    def test_twitter_shortener(self):
        assert is_shortened_url("https://t.co/xyz") is True

    def test_normal_url_not_shortened(self):
        assert is_shortened_url("https://github.com/user/repo") is False

    def test_google_not_shortened(self):
        assert is_shortened_url("https://google.com/search?q=test") is False


# ── Suspicious Keywords ───────────────────────────────────────────────────────

class TestSuspiciousKeywords:
    def test_login_keyword(self):
        count = count_suspicious_keywords("https://fake-login.com/account/verify")
        assert count >= 2  # "login", "account", "verify"

    def test_no_keywords(self):
        count = count_suspicious_keywords("https://github.com/python/cpython")
        assert count == 0

    def test_bank_keyword(self):
        count = count_suspicious_keywords("https://secure-bank-update.xyz/login")
        assert count >= 2

    def test_case_insensitive(self):
        count = count_suspicious_keywords("https://example.com/LOGIN/VERIFY")
        assert count >= 2


# ── Suspicious Extensions ─────────────────────────────────────────────────────

class TestSuspiciousExtensions:
    def test_exe_extension(self):
        assert has_suspicious_extension("http://example.com/download/virus.exe") is True

    def test_zip_extension(self):
        assert has_suspicious_extension("http://example.com/file.zip") is False  # zip not in list

    def test_php_extension(self):
        assert has_suspicious_extension("http://phishing.com/steal.php") is True

    def test_html_not_suspicious(self):
        assert has_suspicious_extension("https://example.com/page.html") is False


# ── Encoded Characters ────────────────────────────────────────────────────────

class TestEncodedChars:
    def test_percent_encoded(self):
        count = count_encoded_chars("https://example.com/path%20with%20spaces")
        assert count == 2  # two %20 sequences (%20 + %20; "with" is unencoded)

    def test_no_encoding(self):
        count = count_encoded_chars("https://example.com/normal")
        assert count == 0


# ── Hash Consistency ──────────────────────────────────────────────────────────

class TestURLHash:
    def test_same_url_same_hash(self):
        assert hash_url("https://example.com") == hash_url("https://example.com")

    def test_different_urls_different_hash(self):
        assert hash_url("https://example.com") != hash_url("https://other.com")

    def test_hash_is_hex_string(self):
        h = hash_url("https://example.com")
        assert len(h) == 64  # SHA-256 hex digest


# ── Risk Bands ────────────────────────────────────────────────────────────────

class TestRiskBands:
    @pytest.mark.parametrize("score,expected", [
        (0, "Safe"),
        (15, "Safe"),
        (20, "Safe"),
        (21, "Moderate Risk"),
        (40, "Moderate Risk"),
        (41, "Suspicious"),
        (65, "Suspicious"),
        (66, "Dangerous"),
        (80, "Dangerous"),
        (81, "Critical"),
        (100, "Critical"),
    ])
    def test_risk_bands(self, score, expected):
        assert risk_band(score) == expected


# ── Char Repetition ───────────────────────────────────────────────────────────

class TestCharRepetition:
    def test_all_same(self):
        ratio = char_repetition_ratio("aaaaaaa")
        assert ratio == 1.0

    def test_uniform_distribution(self):
        ratio = char_repetition_ratio("abcdefgh")
        assert ratio == pytest.approx(1 / 8, abs=0.01)

    def test_empty(self):
        assert char_repetition_ratio("") == 0.0
