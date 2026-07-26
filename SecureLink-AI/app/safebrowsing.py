"""
SecureLink AI — Google Safe Browsing API Client (Async)

Free quota: 10,000 requests/day (as of 2024).
Uses the Lookup API v4 — sends a list of URLs and receives threat info.

Returns a binary flag (flagged / not flagged) plus threat type details.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.cache import get_cache
from app.config import get_settings

logger = logging.getLogger(__name__)

_SB_BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_API_NAME = "safebrowsing"
_TIMEOUT = 10.0


@dataclass
class SafeBrowsingResult:
    """Structured result from the Google Safe Browsing API."""

    available: bool = False
    is_flagged: bool = False          # True if Google has flagged this URL
    threat_types: list[str] = field(default_factory=list)
    platform_types: list[str] = field(default_factory=list)


async def check_safe_browsing(url: str) -> SafeBrowsingResult:
    """
    Check a URL against Google Safe Browsing.

    - Cache-first: returns cached result if available
    - Graceful degradation: returns unavailable result on any error
    """
    settings = get_settings()

    if not settings.has_safe_browsing:
        logger.warning("Google Safe Browsing key not configured — skipping SB check.")
        return SafeBrowsingResult(available=False)

    cache = get_cache()
    cached = cache.get(url, _API_NAME)
    if cached is not None:
        return _parse_sb_response(cached)

    try:
        response_data = await _call_safe_browsing_api(url, settings.google_safe_browsing_key)
        if response_data is not None:
            cache.set(url, _API_NAME, response_data)
            return _parse_sb_response(response_data)
    except Exception as exc:
        logger.warning("Safe Browsing API error: %s — degrading gracefully.", exc)

    return SafeBrowsingResult(available=False)


async def _call_safe_browsing_api(url: str, api_key: str) -> Optional[dict]:
    """Send a Lookup API v4 request."""
    payload = {
        "client": {
            "clientId": "securelink-ai",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        response = await client.post(
            f"{_SB_BASE}?key={api_key}",
            json=payload,
        )
        response.raise_for_status()
        return response.json()


def _parse_sb_response(data: dict) -> SafeBrowsingResult:
    """Parse the Safe Browsing API response."""
    try:
        matches = data.get("matches", [])
        if not matches:
            return SafeBrowsingResult(available=True, is_flagged=False)

        threat_types = list({m.get("threatType", "") for m in matches})
        platform_types = list({m.get("platformType", "") for m in matches})

        return SafeBrowsingResult(
            available=True,
            is_flagged=True,
            threat_types=threat_types,
            platform_types=platform_types,
        )
    except Exception as exc:
        logger.warning("Failed to parse Safe Browsing response: %s", exc)
        return SafeBrowsingResult(available=False)
