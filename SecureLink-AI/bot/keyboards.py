"""
SecureLink AI — Inline Keyboard Markup

Provides feedback buttons (👍 Correct / 👎 Wrong) attached to scan reports.
The scan_id is encoded in the callback_data so the feedback handler can
look up the correct DB record.
"""

from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup


def get_feedback_keyboard(scan_id: int) -> InlineKeyboardMarkup:
    """
    Create the thumbs up/down feedback keyboard for a scan report.

    Callback data format: "feedback:{scan_id}:{was_correct}"
      was_correct: 1 = correct prediction, 0 = wrong prediction
    """
    keyboard = [
        [
            InlineKeyboardButton(
                "👍 Correct",
                callback_data=f"feedback:{scan_id}:1",
            ),
            InlineKeyboardButton(
                "👎 Wrong",
                callback_data=f"feedback:{scan_id}:0",
            ),
        ]
    ]
    return InlineKeyboardMarkup(keyboard)


def get_acknowledged_keyboard() -> InlineKeyboardMarkup:
    """Replaced keyboard after user submits feedback (non-interactive)."""
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("✅ Feedback recorded — thank you!", callback_data="noop")]]
    )
