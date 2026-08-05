"""
SecureLink AI — WHOIS Domain Age Lookup

Wraps python-whois with:
  - asyncio.wait_for timeout (default 5s) to prevent blocking
  - Broad exception handling for inconsistent registrar responses
  - Returns -1 (unknown) on any failure

Production note:
  Cloud-host egress IPs are often rate-limited or blocked by WHOIS servers.
  Expect this feature to be unavailable for 30–40% of URLs in production.
  The model treats -1 as a valid "unknown" value, not as a zero-day domain.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 5


async def get_domain_age_days(domain: str) -> int:
    """
    Return the age of a domain in days, or -1 if unavailable.

    Args:
        domain: The registered domain (e.g. "example.com"), NOT the full URL.
                Use tldextract.extract(url).registered_domain before calling this.

    Returns:
        Integer number of days since domain registration, or -1 if unknown.
    """
    if not domain:
        return -1

    try:
        age_days = await asyncio.wait_for(
            _fetch_domain_age(domain),
            timeout=_TIMEOUT_SECONDS,
        )
        return age_days
    except asyncio.TimeoutError:
        logger.debug("WHOIS timeout for domain: %s", domain)
        return -1
    except Exception as exc:
        logger.debug("WHOIS error for domain %s: %s", domain, exc)
        return -1


async def _fetch_domain_age(domain: str) -> int:
    """Inner coroutine — runs the blocking whois call in a thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _blocking_whois, domain)


def _blocking_whois(domain: str) -> int:
    """
    Synchronous WHOIS lookup (runs in thread pool to avoid blocking the event loop).
    Returns domain age in days, or -1 on any error.
    """
    try:
        import whois
        from datetime import datetime, timezone

        w = whois.whois(domain)
        creation_date = w.creation_date

        # python-whois sometimes returns a list of dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return -1

        # Normalize to UTC-aware datetime
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        delta = now - creation_date
        age_days = delta.days

        # Sanity check — negative age means bad WHOIS data
        if age_days < 0:
            return -1

        logger.debug("WHOIS success: %s is %d days old", domain, age_days)
        return age_days

    except Exception as exc:
        logger.debug("Blocking WHOIS failed for %s: %s", domain, exc)
        return -1
