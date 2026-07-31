"""
SecureLink AI — Per-User Rate Limiter

Prevents abuse of free-tier API quotas by limiting URL submissions per user.
Uses an in-memory dict (no Redis required for single-instance deployment).

Note: resets on restart. For multi-instance deployments, use Redis.
Suitable for Railway/Render single-instance free tier.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict

from app.config import get_settings

logger = logging.getLogger(__name__)

# {user_id: last_request_timestamp}
_last_request: dict[str, float] = defaultdict(float)


def check_rate_limit(user_id: str | int) -> tuple[bool, int]:
    """
    Check if a user is allowed to submit a new URL.

    Args:
        user_id: Telegram user ID (int or str).

    Returns:
        (allowed, seconds_remaining)
        allowed: True if the user can submit; False if rate-limited.
        seconds_remaining: seconds until the cooldown expires (0 if allowed).
    """
    settings = get_settings()
    cooldown = settings.rate_limit_cooldown
    uid = str(user_id)
    now = time.time()
    elapsed = now - _last_request[uid]

    if elapsed < cooldown:
        remaining = int(cooldown - elapsed) + 1
        logger.debug("Rate limit hit | user=%s | wait=%ds", uid, remaining)
        return False, remaining

    _last_request[uid] = now
    return True, 0


def get_cooldown_remaining(user_id: str | int) -> int:
    """Return seconds remaining in the user's cooldown (0 if not rate-limited)."""
    settings = get_settings()
    uid = str(user_id)
    elapsed = time.time() - _last_request[uid]
    remaining = settings.rate_limit_cooldown - elapsed
    return max(0, int(remaining))
