"""
SecureLink AI — Telegram Bot Application Builder

Builds the PTB Application with all handlers registered.
Called from api.py's lifespan (for webhook/production mode)
or can be run standalone for polling (local development).

Run locally:
    python -m bot.telegram_bot
"""

from __future__ import annotations

import asyncio
import logging

from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    filters,
)

from app.config import configure_logging, get_settings
from bot.handlers import (
    about_handler,
    callback_handler,
    feedback_info_handler,
    help_handler,
    start_handler,
    stats_handler,
    url_message_handler,
)

logger = logging.getLogger(__name__)


def build_application() -> Application:
    """
    Build and return the fully configured PTB Application.
    Does not start the bot — start() is called by the lifespan in api.py.
    """
    settings = get_settings()

    if not settings.telegram_bot_token:
        raise ValueError(
            "TELEGRAM_BOT_TOKEN is not set. "
            "Add it to .env or set as an environment variable."
        )

    app = (
        Application.builder()
        .token(settings.telegram_bot_token)
        .build()
    )

    # ── Command handlers ──────────────────────────────────────────────────────
    app.add_handler(CommandHandler("start", start_handler))
    app.add_handler(CommandHandler("help", help_handler))
    app.add_handler(CommandHandler("about", about_handler))
    app.add_handler(CommandHandler("stats", stats_handler))
    app.add_handler(CommandHandler("feedback", feedback_info_handler))

    # ── URL message handler ───────────────────────────────────────────────────
    # Handles any non-command text message (looks for URLs inside)
    app.add_handler(
        MessageHandler(
            filters.TEXT & ~filters.COMMAND,
            url_message_handler,
        )
    )

    # ── Inline keyboard callback handler ──────────────────────────────────────
    app.add_handler(CallbackQueryHandler(callback_handler))

    logger.info("Telegram application built with %d handlers.", len(app.handlers[0]))
    return app


async def _run_polling() -> None:
    """Run the bot in polling mode (local development only)."""
    configure_logging()
    settings = get_settings()

    from app.database import create_tables
    from app.model import load_model

    create_tables()
    load_model(settings.model_path)

    logger.info("Starting SecureLink AI bot in polling mode...")
    app = build_application()

    async with app:
        await app.start()
        logger.info("Bot running. Send /start to your bot on Telegram. Press Ctrl+C to stop.")
        await app.updater.start_polling()

        try:
            # Keep running until interrupted
            await asyncio.Event().wait()
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            await app.updater.stop()
            await app.stop()


if __name__ == "__main__":
    asyncio.run(_run_polling())
