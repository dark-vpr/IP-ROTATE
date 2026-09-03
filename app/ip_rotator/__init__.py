"""IP Rotator v4.1.0 - Production Ready with Advanced WAF Bypass."""

__version__ = "4.1.0"
__all__ = [
    "httpkit",
    "wafbypass", 
    "browser",
    "dialer",
    "pool",
    "relay",
    "server",
    "state",
    "config",
    "log",
]

from . import httpkit
from . import wafbypass
from . import browser
from . import dialer
from . import pool
from . import relay
from . import server
from . import state
from . import config
from . import log

# Convenience exports
from .httpkit import curl_chrome_request, http_client, UA
from .wafbypass import smart_request, get_waf_relay, WafBypassRelay
from .browser import BrowserAutomation, browser_request, get_browser_automation
