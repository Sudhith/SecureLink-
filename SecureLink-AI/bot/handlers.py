"""
SecureLink AI — Telegram Bot Handlers

All command and message handlers for the Telegram bot.

Commands:
  /start    — Welcome message
  /help     — Command reference
  /about    — Project info
  /history  — User's last 10 scans
  /stats    — Global statistics
  /feedback — How to provide feedback

Message handler: Any message containing a URL → trigger analysis
Callback handler: Handles 👍/👎 inline button presses
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import ContextTypes

from app.database import get_global_stats, save_feedback
from app.inference import analyze_url
from app.utils import extract_urls_from_text, is_valid_url, sanitize_for_telegram
from bot.keyboards import get_acknowledged_keyboard, get_feedback_keyboard
from bot.rate_limiter import check_rate_limit

logger = logging.getLogger(__name__)

WELCOME_MESSAGE = """
🔒 <b>Welcome to SecureLink AI!</b>

I analyze suspicious URLs and tell you how dangerous they are — with a Trust Score, specific reasons, and a clear recommendation.

<b>How to use:</b>
Simply send me any URL and I'll analyze it immediately.

<b>Examples:</b>
<code>https://suspicious-bank-login.xyz/verify</code>
<code>http://bit.ly/free-iphone-winner</code>

Type /help to see all commands.
""".strip()

HELP_MESSAGE = """
🔒 <b>SecureLink AI — Command Reference</b>

<b>Analysis:</b>
Just send any URL to analyze it. No command needed.

<b>Commands:</b>
/start    — Show welcome message
/help     — This help text
/about    — About SecureLink AI
/stats    — Global scan statistics
/feedback — How feedback works

<b>Feedback:</b>
After each scan, use the 👍/👎 buttons to tell me if the prediction was correct. This helps improve the model.

<b>Rate limit:</b>
One URL every 10 seconds per user to protect free-tier API quotas.
""".strip()

ABOUT_MESSAGE = """
🔒 <b>About SecureLink AI</b>

SecureLink AI combines machine learning, rule-based heuristics, and threat intelligence to detect phishing and malicious URLs.

<b>How it works:</b>
1. Extracts 23+ structural features from the URL
2. Checks domain age (WHOIS) and SSL certificate
3. Queries VirusTotal, Google Safe Browsing, URLScan.io, OpenPhish (in parallel)
4. Runs a calibrated XGBoost classifier
5. Explains the result with SHAP values + plain-English rules

<b>Tech stack:</b>
Python · FastAPI · XGBoost · SHAP · Telegram Bot API · SQLite

<b>Free tier honest note:</b>
This bot runs on free cloud infrastructure. The first response after a period of inactivity may take a few extra seconds due to cold starts.

Built with 🛡️ by SecureLink AI
""".strip()


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command."""
    await update.message.reply_text(
        WELCOME_MESSAGE,
        parse_mode=ParseMode.HTML,
    )


async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help command."""
    await update.message.reply_text(
        HELP_MESSAGE,
        parse_mode=ParseMode.HTML,
    )


async def about_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /about command."""
    await update.message.reply_text(
        ABOUT_MESSAGE,
        parse_mode=ParseMode.HTML,
    )


async def stats_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /stats — global scan statistics."""
    stats = get_global_stats()
    text = (
        "📊 <b>SecureLink AI Statistics</b>\n\n"
        f"🔍 Total scans: <b>{stats['total_scans']}</b>\n"
        f"📈 Average risk score: <b>{stats['avg_risk_score']}/100</b>\n"
        f"🚨 Dangerous URLs flagged: <b>{stats['flagged_count']}</b>"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def feedback_info_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /feedback command — explain the feedback system."""
    text = (
        "👍 <b>Feedback System</b>\n\n"
        "After every scan, you'll see <b>👍 Correct</b> and <b>👎 Wrong</b> buttons.\n\n"
        "• Tap <b>👍 Correct</b> if the verdict looked right\n"
        "• Tap <b>👎 Wrong</b> if you think the URL was misclassified\n\n"
        "Your feedback is logged and used to identify where the model struggles. "
        "It doesn't immediately change predictions but helps guide retraining."
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def url_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle any text message that contains a URL.
    Runs the full analysis pipeline and sends the report.
    """
    if not update.message or not update.message.text:
        return

    text = update.message.text.strip()
    user_id = str(update.effective_user.id)

    # Extract first URL from the message
    urls = extract_urls_from_text(text)

    # Also check if the entire message is a URL (with or without http://)
    if not urls:
        # Try adding https:// and re-check
        candidate = text if text.startswith("http") else f"https://{text}"
        if is_valid_url(candidate):
            urls = [candidate]

    if not urls:
        # Not a URL — ignore (don't respond to every message)
        return

    url = urls[0]

    if not is_valid_url(url):
        await update.message.reply_text(
            "⚠️ That URL looks malformed. Please send a valid http:// or https:// URL.",
            parse_mode=ParseMode.HTML,
        )
        return

    # ── Rate limiting ─────────────────────────────────────────────────────────
    allowed, wait_seconds = check_rate_limit(user_id)
    if not allowed:
        await update.message.reply_text(
            f"⏳ Please wait {wait_seconds}s before scanning another URL. "
            f"(Free-tier rate limit — protects API quotas for everyone.)",
        )
        return

    # ── Typing indicator ──────────────────────────────────────────────────────
    await update.message.chat.send_action(ChatAction.TYPING)

    try:
        result = await analyze_url(url, user_id=user_id)
    except Exception as exc:
        logger.exception("Analysis failed: %s", exc)
        await update.message.reply_text(
            "❌ Analysis failed. Please try again in a moment.",
        )
        return

    # ── Send report with feedback keyboard ────────────────────────────────────
    reply_markup = None
    if result.scan_id is not None:
        reply_markup = get_feedback_keyboard(result.scan_id)

    await update.message.reply_text(
        result.formatted_report,
        parse_mode=ParseMode.HTML,
        reply_markup=reply_markup,
        disable_web_page_preview=True,  # Don't render the potentially malicious URL
    )


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle inline keyboard button presses (feedback).

    Callback data format: "feedback:{scan_id}:{was_correct}"
    """
    query = update.callback_query
    if not query:
        return

    await query.answer()  # Acknowledge button press immediately

    data = query.data or ""

    if data == "noop":
        return

    if data.startswith("feedback:"):
        parts = data.split(":")
        if len(parts) != 3:
            return

        try:
            scan_id = int(parts[1])
            was_correct = bool(int(parts[2]))
        except ValueError:
            return

        user_id = str(update.effective_user.id)

        try:
            save_feedback(scan_id=scan_id, user_id=user_id, was_correct=was_correct)
        except Exception as exc:
            logger.warning("Failed to save feedback: %s", exc)
            return

        # Replace the keyboard with a thank-you message
        await query.edit_message_reply_markup(
            reply_markup=get_acknowledged_keyboard()
        )

        response = (
            "✅ Thanks for the positive feedback!"
            if was_correct
            else "👎 Thanks — we've logged this as a potential misclassification."
        )
        await query.answer(response, show_alert=False)
