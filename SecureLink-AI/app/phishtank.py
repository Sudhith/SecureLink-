"""
SecureLink AI — PhishTank API Client (Async)

Requires a free API key from https://www.phishtank.com/api_register.php
Gracefully skipped if PHISHTANK_API_KEY is not set.

Rate limits: varies by tier; the client respects the cache TTL to minimize calls.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from app.cache import get_cache
from app.config import get_settings

logger = logging.getLogger(__name__)

_PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"
_API_NAME = "phishtank"
_TIMEOUT = 10.0


@dataclass
class PhishTankResult:
    """Structured result from PhishTank URL check."""

    available: bool = False
    is_phishing: bool = False
    in_database: bool = False
    verified: bool = False
    phish_detail_url: str = ""


async def check_phishtank(url: str) -> PhishTankResult:
    """
    Check a URL against the PhishTank database.

    Skipped gracefully if PHISHTANK_API_KEY is not configured.
    """
    settings = get_settings()

    if not settings.has_phishtank:
        # Not a hard error — just skip
        logger.debug("PhishTank API key not configured — skipping PhishTank check.")
        return PhishTankResult(available=False)

    cache = get_cache()
    cached = cache.get(url, _API_NAME)
    if cached is not None:
        return _parse_phishtank_response(cached)

    try:
        response_data = await _call_phishtank_api(url, settings.phishtank_api_key)
        if response_data is not None:
            cache.set(url, _API_NAME, response_data)
            return _parse_phishtank_response(response_data)
    except Exception as exc:
        logger.warning("PhishTank API error: %s — skipping.", exc)

    return PhishTankResult(available=False)


async def _call_phishtank_api(url: str, api_key: str) -> dict | None:
    """Submit URL check request to PhishTank."""
    import urllib.parse

    encoded_url = urllib.parse.quote(url, safe="")
    payload = f"url={encoded_url}&format=json&app_key={api_key}"

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        response = await client.post(
            _PHISHTANK_URL,
            content=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "SecureLink-AI/1.0",
            },
        )
        response.raise_for_status()
        return response.json()


def _parse_phishtank_response(data: dict) -> PhishTankResult:
    """Parse PhishTank JSON response."""
    try:
        results = data.get("results", {})
        in_database = results.get("in_database", False)
        is_phishing = results.get("valid", False) and results.get("verified", False)
        verified = results.get("verified", False)
        detail_url = results.get("phish_detail_url", "")

        return PhishTankResult(
            available=True,
            is_phishing=is_phishing,
            in_database=in_database,
            verified=verified,
            phish_detail_url=detail_url,
        )
    except Exception as exc:
        logger.warning("Failed to parse PhishTank response: %s", exc)
        return PhishTankResult(available=False)
