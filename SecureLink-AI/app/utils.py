"""
SecureLink AI — Utility Functions

URL validation, sanitization, hashing, and other helpers.
All functions are pure (no side effects) for easy unit testing.
"""

from __future__ import annotations

import hashlib
import html
import logging
import math
import re
import urllib.parse
from collections import Counter

logger = logging.getLogger(__name__)

# ── URL Validation ────────────────────────────────────────────────────────────

# Regex for basic URL structure check (not exhaustive — tldextract handles TLD validation)
_URL_RE = re.compile(
    r"^https?://"  # Scheme
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}|"  # Domain
    r"localhost|"  # or localhost
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # or IPv4
    r"(?::\d+)?"  # optional port
    r"(?:/[^\s]*)?$",  # optional path
    re.IGNORECASE,
)

# URL shorteners to detect (not exhaustive — add more as needed)
KNOWN_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd",
        "buff.ly", "adf.ly", "short.link", "rebrand.ly", "cutt.ly",
        "shorturl.at", "rb.gy", "u.to", "v.gd", "link.tl", "tiny.cc",
    }
)

# Suspicious file extensions that may indicate malicious downloads
SUSPICIOUS_EXTENSIONS = frozenset(
    {".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".js",
     ".jar", ".msi", ".dmg", ".ps1", ".sh", ".php", ".asp", ".aspx"}
)

# Keywords that appear frequently in phishing URLs
SUSPICIOUS_KEYWORDS = frozenset(
    {
        "login", "signin", "sign-in", "logon", "account", "update",
        "verify", "verification", "secure", "security", "bank", "banking",
        "paypal", "amazon", "netflix", "google", "microsoft", "apple",
        "ebay", "confirm", "password", "wallet", "crypto", "invoice",
        "suspended", "limited", "unusual", "activity", "click", "access",
        "alert", "warning", "urgent", "important", "expire", "free",
        "prize", "winner", "congratulations", "claim", "gift", "reward",
    }
)


def is_valid_url(url: str) -> bool:
    """
    Return True if the URL has a valid structure (http/https, non-empty host).
    Does not make a network request.
    """
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if len(url) > 2048:
        return False
    return bool(_URL_RE.match(url))


def normalize_url(url: str) -> str:
    """Strip leading/trailing whitespace and normalize scheme to lowercase."""
    url = url.strip()
    parsed = urllib.parse.urlparse(url)
    # Lowercase scheme and netloc; preserve path/query case
    normalized = parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower())
    return urllib.parse.urlunparse(normalized)


def sanitize_for_telegram(text: str) -> str:
    """
    Escape text sourced from external URLs before including it in Telegram messages.
    This prevents the bot from inadvertently relaying malicious content.
    Telegram HTML parse mode uses <, >, & as special characters.
    """
    return html.escape(str(text), quote=True)


def hash_url(url: str) -> str:
    """Return a SHA-256 hex digest of the normalized URL (used as cache key)."""
    normalized = normalize_url(url)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ── Text Analysis ─────────────────────────────────────────────────────────────


def shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy of a string.
    High entropy (> 3.5) in a URL often indicates random/obfuscated domains.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
    return round(entropy, 4)


def count_suspicious_keywords(url: str) -> int:
    """Count how many suspicious keywords appear in the URL (case-insensitive)."""
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def has_ip_address(url: str) -> bool:
    """Return True if the URL uses a raw IPv4 address instead of a domain name."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    # IPv4 pattern
    ipv4_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    return bool(ipv4_pattern.match(host))


def is_shortened_url(url: str) -> bool:
    """Return True if the domain matches a known URL shortener service."""
    try:
        import tldextract
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        return domain in KNOWN_SHORTENERS
    except Exception:
        return False


def count_encoded_chars(url: str) -> int:
    """Count percent-encoded characters (%XX) in the URL."""
    return len(re.findall(r"%[0-9A-Fa-f]{2}", url))


def has_suspicious_extension(url: str) -> bool:
    """Return True if the URL path ends with a suspicious file extension."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)


def char_repetition_ratio(text: str) -> float:
    """
    Ratio of the most-frequent character to total characters.
    High ratio (e.g., many dashes or zeros) can indicate evasion attempts.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    most_common_count = counts.most_common(1)[0][1]
    return round(most_common_count / len(text), 4)


# ── Score Utilities ───────────────────────────────────────────────────────────


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a float to [lo, hi]."""
    return max(lo, min(hi, value))


def risk_band(score: int) -> str:
    """Map a 0–100 risk score to a human-readable risk band."""
    if score <= 20:
        return "Safe"
    elif score <= 40:
        return "Moderate Risk"
    elif score <= 65:
        return "Suspicious"
    elif score <= 80:
        return "Dangerous"
    else:
        return "Critical"


def recommendation(score: int) -> str:
    """Return an actionable recommendation based on the risk score."""
    if score <= 20:
        return "This URL appears safe. Proceed with normal caution."
    elif score <= 40:
        return "Exercise caution. Verify the source before sharing personal information."
    elif score <= 65:
        return (
            "This URL shows suspicious signals. Avoid entering credentials or payment info."
        )
    elif score <= 80:
        return (
            "Dangerous URL detected. Do not open this website.\n"
            "Do not enter passwords or make payments."
        )
    else:
        return (
            "⚠️ CRITICAL THREAT DETECTED. Avoid opening this website immediately.\n"
            "Do not enter any information. Report this URL to your IT/security team."
        )


def extract_urls_from_text(text: str) -> list[str]:
    """Extract all URLs from a block of text (for Telegram message parsing)."""
    url_pattern = re.compile(
        r"https?://[^\s<>\"']+",
        re.IGNORECASE,
    )
    return url_pattern.findall(text)
