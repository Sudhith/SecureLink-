"""
SecureLink AI — OpenPhish Feed Checker (No API Key Required)

OpenPhish provides a free, periodically updated list of phishing URLs.
We download the feed and check membership. The feed is cached in memory
with a TTL to avoid hammering the endpoint on every request.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_FEED_URL = "https://openphish.com/feed.txt"
_CACHE_SECONDS = 3600  # Refresh feed once per hour

# In-memory feed cache (module-level — shared across requests)
_feed_urls: set[str] = set()
_feed_loaded_at: float = 0.0


async def check_openphish(url: str) -> bool:
    """
    Return True if the URL is in the current OpenPhish feed.

    Feed is loaded once per hour and cached in memory.
    Returns False (not flagged) if the feed is unavailable.
    """
    await _ensure_feed_loaded()
    # Normalize for comparison
    normalized = url.strip().rstrip("/").lower()
    return normalized in _feed_urls


async def _ensure_feed_loaded() -> None:
    """Load or refresh the OpenPhish feed if stale."""
    global _feed_urls, _feed_loaded_at

    now = time.time()
    if _feed_urls and (now - _feed_loaded_at) < _CACHE_SECONDS:
        return  # Still fresh

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(_FEED_URL)
            response.raise_for_status()
            lines = response.text.strip().splitlines()
            _feed_urls = {line.strip().rstrip("/").lower() for line in lines if line.strip()}
            _feed_loaded_at = now
            logger.info("OpenPhish feed loaded: %d entries.", len(_feed_urls))
    except Exception as exc:
        logger.warning("Failed to load OpenPhish feed: %s — continuing without it.", exc)
        # Keep the old feed if it exists; else empty set means no detections
        if not _feed_urls:
            _feed_urls = set()
