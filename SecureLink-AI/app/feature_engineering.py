"""
SecureLink AI — Feature Engineering

Extracts 30+ features from a URL string for ML classification.

Features fall into three groups:
  1. URL structure (from the string itself — fast, no network)
  2. Domain metadata (WHOIS age, SSL info — network calls with timeouts)
  3. Computed signals (entropy, keyword density, etc.)

All features return numeric values. Categoricals (TLD) are handled
as strings and encoded in the model pipeline's ColumnTransformer.

WHOIS reliability note:
  python-whois behaves inconsistently across registrars, and cloud-host
  IPs are sometimes blocked by WHOIS servers. domain_age_days returns -1
  when unavailable. The model is trained to handle -1 as "unknown", NOT
  as a zero-day domain. Expect this feature to be missing for 30–40% of
  production URLs on cloud platforms.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import tldextract

from app.utils import (
    SUSPICIOUS_KEYWORDS,
    char_repetition_ratio,
    count_encoded_chars,
    count_suspicious_keywords,
    has_ip_address,
    has_suspicious_extension,
    is_shortened_url,
    shannon_entropy,
)
from app.whois_lookup import get_domain_age_days
from app.ssl_check import get_ssl_info

logger = logging.getLogger(__name__)


@dataclass
class URLFeatures:
    """
    Structured container for all extracted features.
    Fields map 1-to-1 with the model's training columns.
    """

    # ── URL structure features ────────────────────────────────────────────────
    url_length: int = 0
    num_dots: int = 0
    num_slashes: int = 0
    num_digits: int = 0
    num_special_chars: int = 0
    num_hyphens: int = 0
    num_encoded_chars: int = 0
    num_query_params: int = 0
    directory_depth: int = 0
    has_https: int = 0          # 0 or 1 (int for model compatibility)
    has_ip_address: int = 0
    is_shortened_url: int = 0
    has_suspicious_ext: int = 0
    suspicious_keyword_count: int = 0

    # ── Computed signals ──────────────────────────────────────────────────────
    url_entropy: float = 0.0
    char_repetition: float = 0.0

    # ── Domain features (tldextract — reliable) ───────────────────────────────
    subdomain_count: int = 0
    domain_length: int = 0
    tld: str = "unknown"        # categorical — encoded downstream

    # ── Domain metadata (network, may fail) ───────────────────────────────────
    domain_age_days: int = -1   # -1 = unknown/unavailable
    ssl_is_valid: int = -1      # -1 = unknown, 0 = invalid, 1 = valid
    ssl_days_remaining: int = -1
    ssl_is_self_signed: int = -1

    def to_dict(self) -> dict:
        """Return features as a flat dict (suitable for DataFrame construction)."""
        return {
            "url_length": self.url_length,
            "num_dots": self.num_dots,
            "num_slashes": self.num_slashes,
            "num_digits": self.num_digits,
            "num_special_chars": self.num_special_chars,
            "num_hyphens": self.num_hyphens,
            "num_encoded_chars": self.num_encoded_chars,
            "num_query_params": self.num_query_params,
            "directory_depth": self.directory_depth,
            "has_https": self.has_https,
            "has_ip_address": self.has_ip_address,
            "is_shortened_url": self.is_shortened_url,
            "has_suspicious_ext": self.has_suspicious_ext,
            "suspicious_keyword_count": self.suspicious_keyword_count,
            "url_entropy": self.url_entropy,
            "char_repetition": self.char_repetition,
            "subdomain_count": self.subdomain_count,
            "domain_length": self.domain_length,
            "tld": self.tld,
            "domain_age_days": self.domain_age_days,
            "ssl_is_valid": self.ssl_is_valid,
            "ssl_days_remaining": self.ssl_days_remaining,
            "ssl_is_self_signed": self.ssl_is_self_signed,
        }


def _count_special_chars(url: str) -> int:
    """Count characters that are neither alphanumeric nor common URL delimiters."""
    # Exclude: letters, digits, ://.-_~/?=&#@%+!*,;() — flag the rest
    return len(re.findall(r"[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]", url))


def _count_query_params(url: str) -> int:
    """Return the number of query parameters in the URL."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return 0
    return len(urllib.parse.parse_qs(parsed.query))


def _directory_depth(url: str) -> int:
    """Return the depth of the URL path (number of non-empty path segments)."""
    parsed = urllib.parse.urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]
    return len(segments)


def _extract_domain_info(url: str) -> tuple[int, str, str]:
    """
    Use tldextract for reliable domain/subdomain/TLD parsing.
    Returns (subdomain_count, tld, registered_domain).
    """
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain or ""
    subdomains = [s for s in subdomain.split(".") if s]
    tld = extracted.suffix or "unknown"
    registered_domain = extracted.registered_domain or extracted.domain or ""
    return len(subdomains), tld, registered_domain


async def extract_features(url: str, include_network: bool = True) -> URLFeatures:
    """
    Extract all features from a URL.

    Args:
        url: The raw URL string to analyze.
        include_network: If False, skip WHOIS and SSL checks (faster, for testing).

    Returns:
        URLFeatures dataclass populated with all available signals.
    """
    features = URLFeatures()

    # ── URL structure ─────────────────────────────────────────────────────────
    features.url_length = len(url)
    features.num_dots = url.count(".")
    features.num_slashes = url.count("/")
    features.num_digits = sum(c.isdigit() for c in url)
    features.num_special_chars = _count_special_chars(url)
    features.num_hyphens = url.count("-")
    features.num_encoded_chars = count_encoded_chars(url)
    features.num_query_params = _count_query_params(url)
    features.directory_depth = _directory_depth(url)
    features.has_https = 1 if url.lower().startswith("https://") else 0
    features.has_ip_address = 1 if has_ip_address(url) else 0
    features.is_shortened_url = 1 if is_shortened_url(url) else 0
    features.has_suspicious_ext = 1 if has_suspicious_extension(url) else 0
    features.suspicious_keyword_count = count_suspicious_keywords(url)

    # ── Computed signals ──────────────────────────────────────────────────────
    features.url_entropy = shannon_entropy(url)
    features.char_repetition = char_repetition_ratio(url)

    # ── Domain info (tldextract — reliable, no network) ───────────────────────
    subdomain_count, tld, registered_domain = _extract_domain_info(url)
    features.subdomain_count = subdomain_count
    features.tld = tld
    features.domain_length = len(registered_domain)

    # ── Network-dependent features ────────────────────────────────────────────
    if include_network:
        # WHOIS domain age — may timeout or fail; falls back to -1
        features.domain_age_days = await get_domain_age_days(registered_domain)

        # SSL certificate info
        ssl_info = await get_ssl_info(url)
        if ssl_info is not None:
            features.ssl_is_valid = 1 if ssl_info["is_valid"] else 0
            features.ssl_days_remaining = ssl_info["days_remaining"]
            features.ssl_is_self_signed = 1 if ssl_info["is_self_signed"] else 0

    return features
