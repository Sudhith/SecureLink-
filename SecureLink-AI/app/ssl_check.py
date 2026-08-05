"""
SecureLink AI — SSL Certificate Checker

Uses Python's built-in ssl module (no API key, no third-party dependency).
Checks: validity, days remaining, self-signed vs CA-issued.

All checks run in a thread pool with a timeout to avoid blocking the event loop.
Returns None on any failure (network error, invalid host, timeout, etc.).
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 5
_SSL_PORT = 443


async def get_ssl_info(url: str) -> Optional[dict]:
    """
    Retrieve SSL certificate information for the given URL's host.

    Returns a dict with keys:
        is_valid: bool — True if cert is currently valid
        days_remaining: int — days until cert expiry (-1 if unknown)
        is_self_signed: bool — True if issuer == subject (self-signed)
        issuer: str — certificate issuer (for logging/debug)

    Returns None if the host is not HTTPS, unreachable, or times out.
    """
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        # HTTP-only URL — no SSL info to retrieve
        return {"is_valid": False, "days_remaining": -1, "is_self_signed": False, "issuer": ""}

    host = parsed.hostname
    if not host:
        return None

    try:
        result = await asyncio.wait_for(
            _fetch_ssl_info(host),
            timeout=_TIMEOUT_SECONDS,
        )
        return result
    except asyncio.TimeoutError:
        logger.debug("SSL check timeout for host: %s", host)
        return None
    except Exception as exc:
        logger.debug("SSL check error for %s: %s", host, exc)
        return None


async def _fetch_ssl_info(host: str) -> Optional[dict]:
    """Run the blocking SSL check in a thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _blocking_ssl_check, host)


def _blocking_ssl_check(host: str) -> Optional[dict]:
    """Synchronous SSL certificate retrieval (runs in thread pool)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, _SSL_PORT), timeout=_TIMEOUT_SECONDS) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return None

        # Parse expiry date
        not_after_str = cert.get("notAfter", "")
        days_remaining = -1
        is_valid = False

        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = not_after - now
                days_remaining = delta.days
                is_valid = days_remaining > 0
            except ValueError:
                pass

        # Check if self-signed (issuer == subject)
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        is_self_signed = subject == issuer
        issuer_str = issuer.get("organizationName", issuer.get("commonName", "Unknown"))

        logger.debug(
            "SSL OK | host=%s | valid=%s | days_remaining=%d | self_signed=%s",
            host,
            is_valid,
            days_remaining,
            is_self_signed,
        )

        return {
            "is_valid": is_valid,
            "days_remaining": days_remaining,
            "is_self_signed": is_self_signed,
            "issuer": issuer_str,
        }

    except ssl.SSLCertVerificationError:
        # Invalid or expired certificate
        logger.debug("SSL verification failed for %s", host)
        return {"is_valid": False, "days_remaining": -1, "is_self_signed": False, "issuer": ""}
    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        logger.debug("SSL connection error for %s: %s", host, exc)
        return None
    except Exception as exc:
        logger.debug("Unexpected SSL error for %s: %s", host, exc)
        return None
