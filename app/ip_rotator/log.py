"""Colored, leveled logging + periodic status line."""
import logging
import sys
import threading
import time

_RESET = "\033[0m"
_COLORS = {
    "DEBUG": "\033[90m",
    "INFO": "\033[36m",
    "WARNING": "\033[33m",
    "ERROR": "\033[31m",
    "CRITICAL": "\033[1;41;37m",
    "STATUS": "\033[1;35m",
}


class _Fmt(logging.Formatter):
    def format(self, record):
        if sys.stderr.isatty():
            color = _COLORS.get(record.levelname, "")
            head = f"{color}{time.strftime('%H:%M:%S')} [{record.levelname[:4]}]{_RESET}"
        else:
            head = f"{time.strftime('%H:%M:%S')} [{record.levelname[:4]}]"
        return f"{head} {record.getMessage()}"


def get_logger(name="ip_rotator", level=logging.INFO) -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(_Fmt())
        lg.addHandler(h)
        lg.setLevel(level)
        lg.propagate = False
    return lg


class StatusLine:
    """Prints a one-line status summary on a schedule (rotation events)."""

    def __init__(self, logger, interval=10.0):
        self.log = logger
        self.interval = interval
        self._last = 0.0
        self._lock = threading.Lock()

    def emit(self, text: str, force=False):
        with self._lock:
            now = time.monotonic()
            if force or (now - self._last) >= self.interval:
                self._last = now
                self.log.warning(text)
