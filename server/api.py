"""
server/api.py — Standalone API server for AREE multi-device ingestion.
Provides a standard HTTP service that can run independently or alongside Streamlit.
"""
import argparse
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys, os
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from server.ingest import TelemetryProcessor
from server.device_manager import DeviceManager
from store.db import IncidentDB

logger = logging.getLogger("AREE-ApiServer")

_db = IncidentDB()
_device_mgr = DeviceManager(_db)

class StandaloneApiHandler(BaseHTTPRequestHandler):
    def _send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Device-ID")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors()
        self.end_headers()

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw)
        return {}

    def _get_auth(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/v1/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            devices = _device_mgr.list_all_devices()
            self.wfile.write(json.dumps({
                "status": "healthy",
                "service": "AREE Standalone API",
                "enrolled_devices_count": len(devices),
            }).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        body = self._read_json()
        token = self._get_auth()
        dev_id = self.headers.get("X-Device-ID", "") or body.get("device_id", "")

        if parsed.path == "/api/v1/devices/enroll":
            code, resp = TelemetryProcessor.process_enrollment(body)
        elif parsed.path == "/api/v1/devices/telemetry":
            code, resp = TelemetryProcessor.process_telemetry(dev_id, token, body)
        elif parsed.path == "/api/v1/devices/heartbeat":
            code, resp = TelemetryProcessor.process_heartbeat(dev_id, token)
        elif parsed.path == "/api/v1/devices/remediate/result":
            code, resp = TelemetryProcessor.process_remediation_result(dev_id, token, body)
        else:
            code, resp = 404, {"error": "Endpoint not found"}

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._send_cors()
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode("utf-8"))

def run_server(port: int = 8000, host: str = "0.0.0.0"):
    server = HTTPServer((host, port), StandaloneApiHandler)
    logger.info("AREE Standalone Ingest API serving on http://%s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping API server...")
        server.server_close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AREE Standalone Ingest API")
    parser.add_argument("--port", type=int, default=8000, help="Listen port")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    run_server(args.port, args.host)
