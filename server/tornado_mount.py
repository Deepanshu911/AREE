"""
server/tornado_mount.py — Seamlessly injects AREE API routes into Streamlit's Tornado server.
"""
import gc
import logging
from typing import List, Tuple
import tornado.web

from server.ingest import (
    ApiEnrollHandler,
    ApiHealthHandler,
    ApiHeartbeatHandler,
    ApiRemediationResultHandler,
    ApiTelemetryHandler,
)

logger = logging.getLogger(__name__)

API_ROUTES: List[Tuple[str, type]] = [
    (r"/api/v1/devices/enroll", ApiEnrollHandler),
    (r"/api/v1/devices/telemetry", ApiTelemetryHandler),
    (r"/api/v1/devices/heartbeat", ApiHeartbeatHandler),
    (r"/api/v1/devices/remediate/result", ApiRemediationResultHandler),
    (r"/api/v1/health", ApiHealthHandler),
]

_PATCHED = False

def patch_streamlit_server() -> None:
    """Hooks Streamlit's Server._create_app so API routes are mounted at server bootstrap."""
    global _PATCHED
    if _PATCHED:
        return

    try:
        import streamlit.web.server.server as st_server
        orig_create_app = st_server.Server._create_app

        def custom_create_app(server_self):
            app = orig_create_app(server_self)
            try:
                app.add_handlers(r".*$", API_ROUTES)
                logger.info("Successfully mounted AREE API endpoints on Streamlit Tornado bootstrap.")
            except Exception as e:
                logger.warning("Failed to add custom routes to Tornado app: %s", e)
            return app

        st_server.Server._create_app = custom_create_app
        _PATCHED = True
    except Exception as e:
        logger.warning("Could not patch streamlit.web.server.server: %s", e)


def mount_on_running_tornado() -> bool:
    """Inspects memory via gc to add API handlers to already-running Tornado application."""
    mounted = False
    for obj in gc.get_objects():
        if isinstance(obj, tornado.web.Application):
            try:
                obj.add_handlers(r".*$", API_ROUTES)
                mounted = True
                logger.info("Dynamically mounted AREE API routes on running Tornado application.")
            except Exception as e:
                logger.debug("Failed adding handlers to app object: %s", e)
    return mounted

def ensure_api_mounted():
    """Idempotently guarantees API routes are active on the Streamlit server."""
    patch_streamlit_server()
    mount_on_running_tornado()
