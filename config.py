"""Capture destination config (optional --send path).

The reporting target is NEVER stored in source or baked into any artifact. It is
resolved at run time from the environment of whoever launches the process:

    JWG_TELEGRAM_TOKEN   bot token, from @BotFather
    JWG_TELEGRAM_CHAT    chat/user id you control yourself

Why env and not a config file or a CLI flag: a token pasted into a Python
literal ends up in the .pyc, in git history, and in whatever gets shared around.
A CLI argument is worse — it shows up in every `ps aux` on the machine. Env vars
stay in the launching shell's memory and are the only place a live secret belongs
here.

Fail closed: no token means no send, and the run says so instead of silently
dropping the archive. The audit panel never sends anything; this path exists
only for `jwg.py --send` against your own chat.
"""
from __future__ import annotations

import os

TOKEN_ENV = "JWG_TELEGRAM_TOKEN"
CHAT_ENV = "JWG_TELEGRAM_CHAT"


class DestinationNotConfigured(RuntimeError):
    """Raised when the reporting target is missing or malformed."""


def telegram_destination() -> tuple[str, str]:
    token = os.environ.get(TOKEN_ENV, "").strip()
    chat = os.environ.get(CHAT_ENV, "").strip()
    if not token or not chat:
        raise DestinationNotConfigured(
            f"{TOKEN_ENV} and {CHAT_ENV} must both be set in the environment. "
            "Refusing to run with no destination rather than dropping the capture."
        )
    # A bot token is "<digits>:<44-ish chars>"; a chat id is an int, possibly negative.
    if ":" not in token or len(token) < 20:
        raise DestinationNotConfigured(f"{TOKEN_ENV} does not look like a bot token.")
    try:
        int(chat)
    except ValueError:
        raise DestinationNotConfigured(f"{CHAT_ENV} must be a numeric chat/user id.") from None
    return token, chat


def describe() -> str:
    """Non-secret summary for logs/panel. Never emits the token itself."""
    token = os.environ.get(TOKEN_ENV, "")
    chat = os.environ.get(CHAT_ENV, "")
    if not token or not chat:
        return "destination: UNSET"
    masked = f"{token.split(':')[0]}:****" if ":" in token else "****"
    return f"destination: telegram bot={masked} chat=...{chat[-4:]}"
