"""
SecureLink AI — VirusTotal API Client (Async)

Free tier limits: 4 requests/minute, 500/day.
Every response is cached in SQLite (TTL = CACHE_TTL_HOURS) to avoid
burning quota when multiple users submit the same URL.

Endpoint used: POST /urls (submit URL for analysis) + GET /analyses/{id}
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from app.cache import get_cache
from app.config import get_settings

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_API_NAME = "virustotal"
_TIMEOUT = 20.0


@dataclass
class VTResult:
    """Structured result from a VirusTotal URL analysis."""

    available: bool = False          # False if API is down or key missing
    malicious_count: int = 0         # Number of engines that flagged as malicious
    suspicious_count: int = 0
    total_engines: int = 0
    detection_ratio: float = 0.0     # malicious / total (0.0–1.0)
    categories: list[str] = None     # type: ignore[assignment]
    permalink: str = ""

    def __post_init__(self) -> None:
        if self.categories is None:
            self.categories = []


async def check_virustotal(url: str) -> VTResult:
    """
    Submit a URL to VirusTotal and return a structured result.

    - Checks the local cache first (avoids burning free-tier quota)
    - Submits to VT API only on cache miss
    - Returns an "unavailable" result on any error (graceful degradation)
    """
    settings = get_settings()

    if not settings.has_virustotal:
        logger.warning("VirusTotal API key not configured — skipping VT check.")
        return VTResult(available=False)

    cache = get_cache()
    cached = cache.get(url, _API_NAME)
    if cached is not None:
        logger.debug("VT cache hit for URL.")
        return _parse_vt_response(cached)

    try:
        result_data = await _call_virustotal_api(url, settings.virustotal_api_key)
        if result_data:
            cache.set(url, _API_NAME, result_data)
            return _parse_vt_response(result_data)
    except Exception as exc:
        logger.warning("VirusTotal API error: %s — falling back to no VT data.", exc)

    return VTResult(available=False)


async def _call_virustotal_api(url: str, api_key: str) -> Optional[dict]:
    """
    Submit URL to VT and poll for results.
    VT returns an analysis ID immediately; we poll the analysis endpoint.
    """
    headers = {"x-apikey": api_key, "accept": "application/json"}

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # Step 1: Submit URL for scanning
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        # Try to GET existing report first (saves a submission)
        response = await client.get(f"{_VT_BASE}/urls/{url_id}", headers=headers)

        if response.status_code == 404:
            # No existing report — submit for fresh scan
            submit_resp = await client.post(
                f"{_VT_BASE}/urls",
                headers=headers,
                data={"url": url},
            )
            submit_resp.raise_for_status()
            analysis_id = submit_resp.json()["data"]["id"]

            # Poll analysis result (usually ready within a few seconds)
            for _ in range(3):
                import asyncio
                await asyncio.sleep(3)
                analysis_resp = await client.get(
                    f"{_VT_BASE}/analyses/{analysis_id}",
                    headers=headers,
                )
                if analysis_resp.status_code == 200:
                    data = analysis_resp.json()
                    if data.get("data", {}).get("attributes", {}).get("status") == "completed":
                        return data
            return None

        elif response.status_code == 200:
            return response.json()
        else:
            logger.warning("VT API returned status %d", response.status_code)
            return None


def _parse_vt_response(data: dict) -> VTResult:
    """Extract the key signals from a raw VT API response."""
    try:
        attrs = data.get("data", {}).get("attributes", {})

        # VT analysis response vs URL report response have different structures
        stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        detection_ratio = (malicious / total) if total > 0 else 0.0

        categories = list(attrs.get("categories", {}).values())
        permalink = attrs.get("url", "")

        return VTResult(
            available=True,
            malicious_count=malicious,
            suspicious_count=suspicious,
            total_engines=total,
            detection_ratio=round(detection_ratio, 4),
            categories=categories,
            permalink=permalink,
        )
    except Exception as exc:
        logger.warning("Failed to parse VT response: %s", exc)
        return VTResult(available=False)
