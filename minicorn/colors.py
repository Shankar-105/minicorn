"""
minicorn/colors.py — Colorized logging and formatting utilities.
Provides a rich,style logging experience with:
    - Per-level colored log prefixes (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - HTTP method highlighting (GET=green, POST=blue, PUT=yellow, DELETE=red, etc.)
    - Status code coloring (2xx=green, 3xx=cyan, 4xx=yellow, 5xx=red)
    - Timestamp formatting for request logs
    - WebSocket event highlighting
"""

import logging
import sys
import os
import datetime

# ── ANSI escape codes ───────────────────────────────────────────────────────

# Check if the terminal supports color output
def _supports_color() -> bool:
    """Return True if the terminal likely supports ANSI color codes."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if sys.platform == "win32":
        # Windows Terminal, VS Code terminal, modern cmd.exe support ANSI
        return (
            os.environ.get("WT_SESSION")       # Windows Terminal
            or os.environ.get("TERM_PROGRAM")   # VS Code, etc.
            or os.environ.get("ANSICON")         # ANSICON
            or hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        )
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


USE_COLOR = _supports_color()


class _ANSI:
    """ANSI escape code constants."""
    RESET      = "\033[0m"
    BOLD       = "\033[1m"
    DIM        = "\033[2m"
    ITALIC     = "\033[3m"
    UNDERLINE  = "\033[4m"

    # Foreground colors
    BLACK      = "\033[30m"
    RED        = "\033[31m"
    GREEN      = "\033[32m"
    YELLOW     = "\033[33m"
    BLUE       = "\033[34m"
    MAGENTA    = "\033[35m"
    CYAN       = "\033[36m"
    WHITE      = "\033[37m"

    # Bright foreground colors
    BRIGHT_RED     = "\033[91m"
    BRIGHT_GREEN   = "\033[92m"
    BRIGHT_YELLOW  = "\033[93m"
    BRIGHT_BLUE    = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN    = "\033[96m"
    BRIGHT_WHITE   = "\033[97m"

    # Background colors
    BG_RED     = "\033[41m"
    BG_GREEN   = "\033[42m"
    BG_YELLOW  = "\033[43m"
    BG_BLUE    = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN    = "\033[46m"
    BG_WHITE   = "\033[47m"

    # Bright background colors
    BG_BRIGHT_RED     = "\033[101m"
    BG_BRIGHT_GREEN   = "\033[102m"
    BG_BRIGHT_YELLOW  = "\033[103m"


def _c(code: str, text: str) -> str:
    """Wrap *text* with ANSI *code* only when color is supported."""
    if not USE_COLOR:
        return text
    return f"{code}{text}{_ANSI.RESET}"


# ── Log level styling ───────────────────────────────────────────────────────

_LEVEL_COLORS = {
    "DEBUG":    _ANSI.DIM + _ANSI.CYAN,
    "INFO":     _ANSI.GREEN,
    "WARNING":  _ANSI.YELLOW,
    "ERROR":    _ANSI.BOLD + _ANSI.RED,
    "CRITICAL": _ANSI.BOLD + _ANSI.WHITE + _ANSI.BG_RED,
}

class ColorFormatter(logging.Formatter):
    """
    A logging formatter that applies uvicorn-style colors to log output.

    Format:  ``LEVEL:     message``
    - LEVEL is colored per severity
    - Timestamps are shown in DEBUG mode
    """

    def __init__(self, show_timestamp: bool = False):
        super().__init__()
        self.show_timestamp = show_timestamp

    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        if USE_COLOR:
            color = _LEVEL_COLORS.get(levelname, "")
            colored_level = f"{color}{levelname:<8}{_ANSI.RESET}"
        else:
            colored_level = f"{levelname:<8}"

        message = record.getMessage()

        if self.show_timestamp:
            ts = datetime.datetime.fromtimestamp(record.created).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            dim_ts = _c(_ANSI.DIM, ts)
            return f"{colored_level} {dim_ts} {message}"

        return f"{colored_level} {message}"


# ── HTTP method coloring ────────────────────────────────────────────────────

_METHOD_COLORS = {
    "GET":     _ANSI.BOLD + _ANSI.GREEN,
    "POST":    _ANSI.BOLD + _ANSI.BLUE,
    "PUT":     _ANSI.BOLD + _ANSI.YELLOW,
    "PATCH":   _ANSI.BOLD + _ANSI.MAGENTA,
    "DELETE":  _ANSI.BOLD + _ANSI.RED,
    "HEAD":    _ANSI.BOLD + _ANSI.CYAN,
    "OPTIONS": _ANSI.BOLD + _ANSI.WHITE,
}


def color_method(method: str) -> str:
    """Return the HTTP method string with appropriate color coding."""
    color = _METHOD_COLORS.get(method.upper(), _ANSI.BOLD)
    return _c(color, f"{method:<7}")


# ── HTTP status code coloring ───────────────────────────────────────────────

def color_status(status_code) -> str:
    """Return the status code string colored by category."""
    code = int(str(status_code).split()[0]) if isinstance(status_code, str) else int(status_code)
    code_str = str(code)

    if 200 <= code < 300:
        return _c(_ANSI.BOLD + _ANSI.GREEN, code_str)
    elif 300 <= code < 400:
        return _c(_ANSI.BOLD + _ANSI.CYAN, code_str)
    elif 400 <= code < 500:
        return _c(_ANSI.BOLD + _ANSI.YELLOW, code_str)
    elif code >= 500:
        return _c(_ANSI.BOLD + _ANSI.RED, code_str)
    else:
        return _c(_ANSI.BOLD, code_str)


# ── Request / response log formatting ──────────────────────────────────────

def format_request_log(
    client_ip: str,
    client_port: int,
    method: str,
    path: str,
    http_version: str = "",
) -> str:
    """
    Format an incoming request log line.

    Example output:
        127.0.0.1:51234 - GET     /api/items HTTP/1.1
    """
    addr = _c(_ANSI.DIM, f"{client_ip}:{client_port}")
    m = color_method(method)
    p = _c(_ANSI.BOLD, path)
    v = _c(_ANSI.DIM, http_version) if http_version else ""
    return f"{addr} {_c(_ANSI.DIM, '-')} {m} {p} {v}".rstrip()


def format_response_log(
    client_ip: str,
    client_port: int,
    method: str,
    path: str,
    status_code,
) -> str:
    """
    Format a response log line.

    Example output:
        127.0.0.1:51234 - GET     /api/items  → 200
    """
    addr = _c(_ANSI.DIM, f"{client_ip}:{client_port}")
    m = color_method(method)
    p = _c(_ANSI.BOLD, path)
    arrow = _c(_ANSI.DIM, "→")
    status = color_status(status_code)
    return f"{addr} {_c(_ANSI.DIM, '-')} {m} {p} {arrow} {status}"


# ── WebSocket log formatting ───────────────────────────────────────────────

def format_ws_event(
    client_ip: str,
    client_port: int,
    event: str,
    path: str,
    detail: str = "",
) -> str:
    """
    Format a WebSocket event log line.

    Events: connected, accepted, message, disconnected, ping, pong, error
    """
    addr = _c(_ANSI.DIM, f"{client_ip}:{client_port}")

    _WS_EVENT_COLORS = {
        "connected":    _ANSI.BRIGHT_GREEN,
        "accepted":     _ANSI.BOLD + _ANSI.GREEN,
        "message":      _ANSI.CYAN,
        "disconnected": _ANSI.YELLOW,
        "closed":       _ANSI.YELLOW,
        "ping":         _ANSI.DIM + _ANSI.CYAN,
        "pong":         _ANSI.DIM + _ANSI.CYAN,
        "error":        _ANSI.BOLD + _ANSI.RED,
        "timeout":      _ANSI.BOLD + _ANSI.YELLOW,
    }

    ws_badge = _c(_ANSI.BOLD + _ANSI.MAGENTA, "WS")
    event_color = _WS_EVENT_COLORS.get(event, "")
    colored_event = _c(event_color, event)
    colored_path = _c(_ANSI.BOLD, path)

    parts = [addr, _c(_ANSI.DIM, "-"), ws_badge, colored_event, colored_path]
    if detail:
        parts.append(_c(_ANSI.DIM, f"({detail})"))
    return " ".join(parts)


# ── Startup banner helpers ──────────────────────────────────────────────────

def format_banner_line(label: str, value: str) -> str:
    """Format a key-value line for the startup banner."""
    colored_label = _c(_ANSI.DIM, f"  {label:<12}")
    return f"{colored_label} {value}"


def format_banner_title(name: str, version: str) -> str:
    """Format the main title line of the startup banner."""
    return _c(_ANSI.BOLD + _ANSI.BRIGHT_CYAN, f"  {name}") + " " + _c(_ANSI.DIM, f"v{version}")


def format_banner_separator() -> str:
    """Return a dim horizontal separator for the banner."""
    return _c(_ANSI.DIM, "  " + "─" * 40)


def format_banner_tag(text: str, color: str = _ANSI.CYAN) -> str:
    """Format a tag/badge in the banner (e.g., ASGI, WSGI, reload)."""
    return _c(_ANSI.BOLD + color, text)
