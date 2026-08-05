"""
SecureLink AI — Report Generator

Formats the analysis result into the exact Telegram message format specified.
All externally-sourced text is sanitized before inclusion to prevent the bot
from becoming a relay for malicious content (e.g., adversarial page titles).
"""

from __future__ import annotations

from app.utils import sanitize_for_telegram


def _score_emoji(score: int) -> str:
    """Return an emoji that reflects the risk level."""
    if score <= 20:
        return "✅"
    elif score <= 40:
        return "🟡"
    elif score <= 65:
        return "🟠"
    elif score <= 80:
        return "🔴"
    else:
        return "🚨"


def _confidence_pct(confidence: float) -> int:
    """Convert ML probability to a display confidence percentage."""
    # The raw ML prob is the phishing probability. For "Confidence in the prediction",
    # we display how confident the model is in whichever class it chose.
    return int(max(confidence, 1 - confidence) * 100)


def generate_report(result) -> str:
    """
    Generate the formatted Telegram report string.

    Args:
        result: AnalysisResult from inference.py

    Returns:
        Formatted string ready for Telegram (uses HTML parse mode).
    """
    emoji = _score_emoji(result.risk_score)
    confidence_pct = _confidence_pct(result.confidence)

    # Sanitize the URL before including in message
    safe_url = sanitize_for_telegram(result.normalized_url)
    # Truncate very long URLs for display
    display_url = safe_url if len(safe_url) <= 60 else safe_url[:57] + "..."

    reasons_text = "\n".join(result.reasons) if result.reasons else "• No specific signals detected"

    # API availability notice
    api_notices = []
    if not result.vt_available:
        api_notices.append("VirusTotal")
    if not result.sb_available:
        api_notices.append("Safe Browsing")
    fallback_note = ""
    if api_notices:
        fallback_note = (
            f"\n⚠️ <i>Note: {', '.join(api_notices)} unavailable — "
            f"score based on ML + heuristics only.</i>"
        )

    # Synthetic model banner
    synthetic_banner = ""
    if result.is_synthetic_model:
        synthetic_banner = (
            "\n\n🔬 <i>⚠️ Demo model active (synthetic training data). "
            "Retrain on real data for production accuracy.</i>"
        )

    report = (
        f"🔒 <b>SecureLink AI Report</b>\n"
        f"{'─' * 30}\n\n"
        f"🔗 <b>URL:</b> <code>{display_url}</code>\n\n"
        f"{emoji} <b>Risk Score: {result.risk_score}/100</b>\n"
        f"📊 <b>Verdict:</b> {result.prediction}\n"
        f"🎯 <b>Confidence:</b> {confidence_pct}%\n\n"
        f"<b>Top Risk Signals:</b>\n"
        f"{reasons_text}\n\n"
        f"<b>Recommendation:</b>\n"
        f"{sanitize_for_telegram(result.recommendation_text)}"
        f"{fallback_note}"
        f"{synthetic_banner}\n\n"
        f"<i>Was this prediction correct?</i>"
    )

    return report


def generate_history_entry(scan) -> str:
    """Format a compact history entry for the /history command."""
    emoji = _score_emoji(scan.risk_score)
    url_display = scan.url[:40] + "..." if len(scan.url) > 40 else scan.url
    ts = scan.timestamp.strftime("%d %b %H:%M")
    return f"{emoji} <code>{sanitize_for_telegram(url_display)}</code> — <b>{scan.risk_score}/100</b> <i>({ts})</i>"
