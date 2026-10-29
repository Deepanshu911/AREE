"""
visitor/session.py — Isolated, zero-install visitor session management.
Ensures every web visitor gets their own private, rate-limited session
with strictly validated browser-observed capabilities.
"""
import datetime
import html
import re
import secrets
import time
from typing import Any, Dict, List, Optional


def generate_visitor_id() -> str:
    """Generates a secure, cryptographically random visitor session ID."""
    return f"vis-{secrets.token_hex(4)}"


def sanitize_str(val: Any, max_len: int = 120, default: str = "Unknown") -> str:
    """Sanitizes and bounds string inputs to prevent XSS and memory inflation."""
    if val is None:
        return default
    cleaned = html.escape(str(val).strip())
    # Strip non-printable characters
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", cleaned)
    return cleaned[:max_len] if cleaned else default


def validate_number(val: Any, min_val: float = 0.0, max_val: float = 100000.0, default: Optional[float] = None) -> Optional[float]:
    """Validates and bounds numeric metrics from browser telemetry."""
    try:
        num = float(val)
        if min_val <= num <= max_val:
            return round(num, 2)
        return default
    except (ValueError, TypeError):
        return default


class VisitorSession:
    """
    Encapsulates a single visitor's browser session.
    Strictly isolated per visitor with input validation and rate-limiting.
    """

    def __init__(self, visitor_id: Optional[str] = None):
        self.session_id = visitor_id if (visitor_id and re.match(r"^vis-[0-9a-f]{8,}$", visitor_id)) else generate_visitor_id()
        now = datetime.datetime.utcnow().isoformat()
        self.created_at = now
        self.last_seen = now
        self.is_connected = True
        self._last_update_ts = 0.0

        # Browser and Platform Telemetry
        self.browser_name = "Detecting..."
        self.browser_version = ""
        self.os_name = "Detecting..."
        self.user_agent = ""
        self.language = "en"

        # Hardware Capabilities (Browser-Reported)
        self.logical_cores: Optional[int] = None
        self.device_memory_gib: Optional[float] = None
        self.screen_width: Optional[int] = None
        self.screen_height: Optional[int] = None
        self.viewport_width: Optional[int] = None
        self.viewport_height: Optional[int] = None
        self.color_depth: Optional[int] = None
        self.pixel_ratio: Optional[float] = None

        # Network Connectivity
        self.is_online = True
        self.effective_type = "Unknown"
        self.downlink_mbps: Optional[float] = None
        self.rtt_ms: Optional[float] = None

        # Page & Browser Performance
        self.page_load_ms: Optional[float] = None
        self.ttfb_ms: Optional[float] = None
        self.dom_interactive_ms: Optional[float] = None
        self.dom_complete_ms: Optional[float] = None
        self.render_latency_ms: Optional[float] = None
        self.js_heap_used_mb: Optional[float] = None

    def update_from_client_payload(self, payload: Dict[str, Any]) -> bool:
        """
        Safely ingests client-reported browser diagnostics.
        Enforces rate limiting (min 0.5s between updates) and strict validation.
        """
        now_ts = time.time()
        # Rate limit updates to 1 per 0.5s
        if now_ts - self._last_update_ts < 0.5:
            return False

        if not isinstance(payload, dict):
            return False

        self._last_update_ts = now_ts
        self.last_seen = datetime.datetime.utcnow().isoformat()
        self.is_connected = True

        # Browser info
        if "browser" in payload:
            self.browser_name = sanitize_str(payload.get("browser"), max_len=60, default="Standard Browser")
        if "os" in payload:
            self.os_name = sanitize_str(payload.get("os"), max_len=60, default="Client OS")
        if "user_agent" in payload:
            self.user_agent = sanitize_str(payload.get("user_agent"), max_len=300, default="")
        if "language" in payload:
            self.language = sanitize_str(payload.get("language"), max_len=20, default="en")

        # Hardware capabilities
        if "cores" in payload:
            cores_val = validate_number(payload.get("cores"), min_val=1, max_val=256)
            if cores_val is not None:
                self.logical_cores = int(cores_val)

        if "memory_gib" in payload:
            self.device_memory_gib = validate_number(payload.get("memory_gib"), min_val=0.25, max_val=256.0)

        if "screen_width" in payload:
            w_val = validate_number(payload.get("screen_width"), min_val=100, max_val=16000)
            if w_val is not None:
                self.screen_width = int(w_val)

        if "screen_height" in payload:
            h_val = validate_number(payload.get("screen_height"), min_val=100, max_val=16000)
            if h_val is not None:
                self.screen_height = int(h_val)

        if "viewport_width" in payload:
            vw_val = validate_number(payload.get("viewport_width"), min_val=100, max_val=16000)
            if vw_val is not None:
                self.viewport_width = int(vw_val)

        if "viewport_height" in payload:
            vh_val = validate_number(payload.get("viewport_height"), min_val=100, max_val=16000)
            if vh_val is not None:
                self.viewport_height = int(vh_val)

        if "pixel_ratio" in payload:
            self.pixel_ratio = validate_number(payload.get("pixel_ratio"), min_val=0.5, max_val=10.0)

        # Network
        if "online" in payload:
            self.is_online = bool(payload.get("online"))
        if "effective_type" in payload:
            self.effective_type = sanitize_str(payload.get("effective_type"), max_len=20, default="Unknown")
        if "downlink_mbps" in payload:
            self.downlink_mbps = validate_number(payload.get("downlink_mbps"), min_val=0.01, max_val=10000.0)
        if "rtt_ms" in payload:
            self.rtt_ms = validate_number(payload.get("rtt_ms"), min_val=0.0, max_val=60000.0)

        # Performance
        if "page_load_ms" in payload:
            self.page_load_ms = validate_number(payload.get("page_load_ms"), min_val=0.0, max_val=60000.0)
        if "ttfb_ms" in payload:
            self.ttfb_ms = validate_number(payload.get("ttfb_ms"), min_val=0.0, max_val=60000.0)
        if "dom_complete_ms" in payload:
            self.dom_complete_ms = validate_number(payload.get("dom_complete_ms"), min_val=0.0, max_val=60000.0)
        if "render_latency_ms" in payload:
            self.render_latency_ms = validate_number(payload.get("render_latency_ms"), min_val=0.0, max_val=10000.0)
        if "js_heap_used_mb" in payload:
            self.js_heap_used_mb = validate_number(payload.get("js_heap_used_mb"), min_val=0.0, max_val=32000.0)

        return True

    def get_capability_matrix(self) -> List[Dict[str, str]]:
        """
        Returns honest transparency table distinguishing genuinely observed browser
        capabilities from OS-level internals protected by the browser sandbox.
        """
        cores_str = f"{self.logical_cores} Cores" if self.logical_cores else "Available via navigator.hardwareConcurrency"
        res_str = f"{self.screen_width}x{self.screen_height} (Viewport {self.viewport_width}x{self.viewport_height})" if self.screen_width else "Available via window.screen"
        net_str = f"{'🟢 Online' if self.is_online else '🔴 Offline'} ({self.effective_type})"
        perf_str = f"{self.page_load_ms:.0f} ms" if self.page_load_ms else "Available via Navigation Timing API"
        mem_str = f"{self.device_memory_gib} GiB (Approx)" if self.device_memory_gib else "Restricted / Chromium Only"

        return [
            {
                "metric": "Operating System & Browser",
                "status": "🟢 Observed",
                "value": f"{self.os_name} / {self.browser_name}",
                "boundary": "Accessible via User-Agent & Client Hints APIs",
            },
            {
                "metric": "Logical CPU Cores",
                "status": "🟢 Observed",
                "value": cores_str,
                "boundary": "Accessible via navigator.hardwareConcurrency",
            },
            {
                "metric": "Screen & Viewport Resolution",
                "status": "🟢 Observed",
                "value": res_str,
                "boundary": "Accessible via window.screen and window.innerDimensions",
            },
            {
                "metric": "Network Connectivity & Type",
                "status": "🟢 Observed",
                "value": net_str,
                "boundary": "Accessible via navigator.onLine & Network Information API",
            },
            {
                "metric": "Browser Page Performance",
                "status": "🟢 Observed",
                "value": perf_str,
                "boundary": "Accessible via Performance & Navigation Timing APIs",
            },
            {
                "metric": "Device Memory (Approx)",
                "status": "🟡 Restricted",
                "value": mem_str,
                "boundary": "Approximate hardware tier; coarse-grained to prevent fingerprinting",
            },
            {
                "metric": "Host CPU Utilization %",
                "status": "🔒 Not Available in Browser Mode",
                "value": "Unavailable (Requires Local Agent)",
                "boundary": "Browser sandbox isolates web apps from OS task scheduler",
            },
            {
                "metric": "Physical RAM & Swap Usage",
                "status": "🔒 Not Available in Browser Mode",
                "value": "Unavailable (Requires Local Agent)",
                "boundary": "Direct kernel virtual memory metrics require OS privileges",
            },
            {
                "metric": "Local Disk Partitions & I/O",
                "status": "🔒 Not Available in Browser Mode",
                "value": "Unavailable (Requires Local Agent)",
                "boundary": "Origin policy forbids inspecting host disk partitions or I/O counters",
            },
            {
                "metric": "Running Operating System Processes",
                "status": "🔒 Not Available in Browser Mode",
                "value": "Unavailable (Requires Local Agent)",
                "boundary": "Inspecting host process tables requires OS process management rights",
            },
            {
                "metric": "Raw Network Socket Sniffing",
                "status": "🔒 Not Available in Browser Mode",
                "value": "Unavailable (Requires Local Agent)",
                "boundary": "Raw socket capture is restricted by TCP/IP stack and browser CORS",
            },
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes visitor session to safe dict."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "is_connected": self.is_connected,
            "browser": self.browser_name,
            "os": self.os_name,
            "cores": self.logical_cores,
            "memory_gib": self.device_memory_gib,
            "screen_width": self.screen_width,
            "screen_height": self.screen_height,
            "viewport_width": self.viewport_width,
            "viewport_height": self.viewport_height,
            "is_online": self.is_online,
            "effective_type": self.effective_type,
            "page_load_ms": self.page_load_ms,
            "render_latency_ms": self.render_latency_ms,
        }
