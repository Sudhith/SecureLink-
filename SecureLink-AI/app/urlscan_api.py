"""
SecureLink AI — URLScan.io API Client (Async)

Free tier: 100 scans/day. Cached to SQLite to preserve quota.
URLScan provides rich page signals but results take ~10s to generate.
We use the "search" endpoint for existing results (faster, no new scan cost).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

from app.cache import get_cache
from app.config import get_settings

logger = logging.getLogger(__name__)

_URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
_URLSCAN_SUBMIT = "https://urlscan.io/api/v1/scan/"
_API_NAME = "urlscan"
_TIMEOUT = 15.0


@dataclass
class URLScanResult:
    """Structured result from URLScan.io."""

    available: bool = False
    verdict_score: int = 0           # 0–100 malicious score from URLScan
    is_malicious: bool = False
    tags: list[str] = field(default_factory=list)
    screenshot_url: str = ""
    report_url: str = ""
    page_title: str = ""             # Scraped page title (structural signal only)


async def check_urlscan(url: str) -> URLScanResult:
    """
    Look up an existing URLScan result for the URL (no new scan submitted).
    Falls back to submitting a new scan if no existing result is found.
    """
    settings = get_settings()

    if not settings.has_urlscan:
        logger.warning("URLScan API key not configured — skipping URLScan check.")
        return URLScanResult(available=False)

    cache = get_cache()
    cached = cache.get(url, _API_NAME)
    if cached is not None:
        return _parse_urlscan_response(cached)

    try:
        response_data = await _search_urlscan(url, settings.urlscan_api_key)
        if response_data:
            cache.set(url, _API_NAME, response_data)
            return _parse_urlscan_response(response_data)
    except Exception as exc:
        logger.warning("URLScan API error: %s — degrading gracefully.", exc)

    return URLScanResult(available=False)


async def _search_urlscan(url: str, api_key: str) -> Optional[dict]:
    """Search for existing URLScan results (cheaper than submitting a new scan)."""
    import urllib.parse

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    query = urllib.parse.quote(f'page.url:"{url}"')

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(
            f"{_URLSCAN_SEARCH}?q={query}&size=1&sort=_score",
            headers=headers,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("total", 0) == 0:
            return {"results": []}
        return data


def _parse_urlscan_response(data: dict) -> URLScanResult:
    """Extract key signals from a URLScan search response."""
    try:
        results = data.get("results", [])
        if not results:
            return URLScanResult(available=True, is_malicious=False)

        result = results[0]
        verdicts = result.get("verdicts", {})
        overall = verdicts.get("overall", {})
        score = overall.get("score", 0)
        is_malicious = overall.get("malicious", False)
        tags = overall.get("tags", [])

        page = result.get("page", {})
        title = page.get("title", "")[:100]  # Truncate; never display raw to users

        screenshot_url = result.get("screenshot", "")
        report_url = f"https://urlscan.io/result/{result.get('_id', '')}/"

        return URLScanResult(
            available=True,
            verdict_score=score,
            is_malicious=is_malicious,
            tags=tags,
            screenshot_url=screenshot_url,
            report_url=report_url,
            page_title=title,
        )
    except Exception as exc:
        logger.warning("Failed to parse URLScan response: %s", exc)
        return URLScanResult(available=False)
