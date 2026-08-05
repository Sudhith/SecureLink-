"""
SecureLink AI — SQLite TTL Cache for External API Responses

Wraps the database-layer cache functions with a clean interface.
Keyed by (url_hash, api_name) pairs with a configurable TTL.

Design goals:
  - Respect free-tier rate limits (VT: 4 req/min, 500/day)
  - Return cached results instantly when available
  - Gracefully handle a cold cache (first scan of a URL)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.config import get_settings
from app.database import get_cached_api_response, set_cached_api_response
from app.utils import hash_url

logger = logging.getLogger(__name__)


class APICache:
    """
    TTL-based cache for external API responses.

    Usage:
        cache = APICache()
        result = cache.get("https://example.com", "virustotal")
        if result is None:
            result = await call_virustotal(url)
            cache.set("https://example.com", "virustotal", result)
    """

    def __init__(self, ttl_hours: Optional[int] = None) -> None:
        settings = get_settings()
        self.ttl_hours = ttl_hours or settings.cache_ttl_hours

    def _expires_at(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(hours=self.ttl_hours)

    def get(self, url: str, api_name: str) -> Optional[dict[str, Any]]:
        """
        Return a cached API response if available and not expired.
        Returns None on cache miss (caller should fetch from the live API).
        """
        url_hash = hash_url(url)
        result = get_cached_api_response(url_hash, api_name)
        if result is not None:
            logger.debug("Cache HIT  | api=%s | url_hash=%s...", api_name, url_hash[:8])
        else:
            logger.debug("Cache MISS | api=%s | url_hash=%s...", api_name, url_hash[:8])
        return result

    def set(self, url: str, api_name: str, response: dict[str, Any]) -> None:
        """Store an API response in the cache with the configured TTL."""
        url_hash = hash_url(url)
        set_cached_api_response(
            url_hash=url_hash,
            api_name=api_name,
            response=response,
            expires_at=self._expires_at(),
        )
        logger.debug("Cache SET  | api=%s | url_hash=%s...", api_name, url_hash[:8])

    def has(self, url: str, api_name: str) -> bool:
        """Return True if a valid (non-expired) cache entry exists."""
        return self.get(url, api_name) is not None


# Module-level singleton
_cache_instance: Optional[APICache] = None


def get_cache() -> APICache:
    """Return the module-level cache singleton."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = APICache()
    return _cache_instance
