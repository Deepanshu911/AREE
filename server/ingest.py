"""
server/ingest.py — API ingest controllers and Tornado route handlers for multi-device telemetry.
"""
import datetime
import json
import logging
from typing import Any, Dict, Optional, Tuple
import tornado.web

from agent.collector import DiskPartition, ProcessInfo, SystemSnapshot
from agent.detector import DetectionEngine, Incident
from config.config import load_config
from engine.risk import compute_oss, compute_re
from server.device_manager import DeviceManager
from store.db import IncidentDB

logger = logging.getLogger(__name__)

# Singleton instances for server-side processing
_db = IncidentDB()
_device_mgr = DeviceManager(_db)
_config = load_config()
_detector = DetectionEngine(_config)

class TelemetryProcessor:
    """Core business logic for handling device telemetry, incident detection, and risk scoring."""

    @staticmethod
    def process_enrollment(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        device_name = payload.get("device_name", "").strip() or "Unnamed Device"
        os_type = payload.get("os_type", "Unknown")
        custom_id = payload.get("device_id")
        metadata = payload.get("metadata", {})

        device_id, raw_token = _device_mgr.enroll_device(
            device_name=device_name,
            os_type=os_type,
            custom_id=custom_id,
            metadata=metadata,
        )

        return 201, {
            "status": "enrolled",
            "device_id": device_id,
            "token": raw_token,
            "message": "Device successfully enrolled. Store this token securely; it will not be shown again.",
        }

    @staticmethod
    def process_telemetry(device_id: str, raw_token: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        # Authenticate device
        if not _device_mgr.authenticate(device_id, raw_token):
            return 401, {"error": "Unauthorized: Invalid device ID or token."}

        # Update heartbeat
        _device_mgr.record_heartbeat(device_id)

        # Reconstruct SystemSnapshot from agent payload
        partitions = [
            DiskPartition(
                mountpoint=p.get("mountpoint", ""),
                total_gb=float(p.get("total_gb", 0)),
                used_gb=float(p.get("used_gb", 0)),
                free_gb=float(p.get("free_gb", 0)),
                percent_used=float(p.get("percent_used", 0)),
            )
            for p in payload.get("disk_partitions", [])
        ]

        processes = [
            ProcessInfo(
                pid=int(proc.get("pid", 0)),
                name=proc.get("name", "unknown"),
                cpu_percent=float(proc.get("cpu_percent", 0.0)),
                memory_percent=float(proc.get("memory_percent", 0.0)),
                status=proc.get("status", "running"),
            )
            for proc in payload.get("top_processes", [])
        ]

        now = datetime.datetime.utcnow()
        snapshot = SystemSnapshot(
            timestamp=now,
            data_source="enrolled_agent",
            cpu_percent=float(payload.get("cpu_percent", 0.0)),
            cpu_per_core=[float(c) for c in payload.get("cpu_per_core", [])],
            ram_percent=float(payload.get("ram_percent", 0.0)),
            ram_available_gb=float(payload.get("ram_available_gb", 0.0)),
            ram_total_gb=float(payload.get("ram_total_gb", 0.0)),
            disk_partitions=partitions,
            net_bytes_sent_ps=float(payload.get("net_bytes_sent_ps", 0.0)),
            net_bytes_recv_ps=float(payload.get("net_bytes_recv_ps", 0.0)),
            top_processes=processes,
            uptime_seconds=float(payload.get("uptime_seconds", 0.0)),
            errors=payload.get("errors", []),
        )

        # 1. Save Snapshot to DB
        _db.save_snapshot(snapshot, device_id=device_id)

        # 2. Run Problem Detection
        incidents = _detector.detect(snapshot)
        for inc in incidents:
            # Stamp with device_id
            inc.device_id = device_id
            _db.save_incident(inc, device_id=device_id)

        # 3. Calculate Risk Energy (RE)
        oss = compute_oss(
            cpu_pct=snapshot.cpu_percent,
            ram_pct=snapshot.ram_percent,
            latency_ms=float(payload.get("latency_ms", 50.0)),
        )
        tes = float(payload.get("threat_score", 0.1))
        re = compute_re(oss=oss, tes=tes, dss=0.0, bcs=0.5)

        # 4. Check for Pending Remote Remediation Tasks
        pending_tasks = _db.get_pending_tasks(device_id)

        return 200, {
            "status": "ok",
            "device_id": device_id,
            "re_score": re,
            "incidents_detected": len(incidents),
            "pending_tasks": pending_tasks,
        }

    @staticmethod
    def process_heartbeat(device_id: str, raw_token: str) -> Tuple[int, Dict[str, Any]]:
        if not _device_mgr.authenticate(device_id, raw_token):
            return 401, {"error": "Unauthorized: Invalid device ID or token."}
        _device_mgr.record_heartbeat(device_id)
        pending = _db.get_pending_tasks(device_id)
        return 200, {"status": "alive", "pending_tasks": pending}

    @staticmethod
    def process_remediation_result(device_id: str, raw_token: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        if not _device_mgr.authenticate(device_id, raw_token):
            return 401, {"error": "Unauthorized."}

        task_id = payload.get("task_id", "")
        result_msg = payload.get("result", "")
        before_val = payload.get("before_value")
        after_val = payload.get("after_value")

        _db.complete_task(task_id, result=result_msg, before_val=before_val, after_val=after_val)
        _db.save_remediation_log({
            "device_id": device_id,
            "incident_id": payload.get("incident_id"),
            "action": payload.get("action_type", "REMOTE_FIX"),
            "result": result_msg,
            "before_value": before_val,
            "after_value": after_val,
            "duration_seconds": float(payload.get("duration_seconds", 0.0)),
            "operator": "AGENT_LOCAL_EXEC",
        }, device_id=device_id)

        return 200, {"status": "recorded", "task_id": task_id}


# ── Tornado Request Handlers ──────────────────────────────────────────────────

class BaseApiHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Device-ID")
        self.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

    def options(self, *args, **kwargs):
        self.set_status(204)
        self.finish()

    def parse_body(self) -> Dict[str, Any]:
        try:
            return json.loads(self.request.body.decode("utf-8")) if self.request.body else {}
        except Exception:
            return {}

    def get_auth_token(self) -> str:
        auth_header = self.request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        return self.get_argument("token", "")


class ApiEnrollHandler(BaseApiHandler):
    def post(self):
        payload = self.parse_body()
        status_code, resp = TelemetryProcessor.process_enrollment(payload)
        self.set_status(status_code)
        self.write(json.dumps(resp))


class ApiTelemetryHandler(BaseApiHandler):
    def post(self):
        device_id = self.request.headers.get("X-Device-ID", "") or self.get_argument("device_id", "")
        token = self.get_auth_token()
        payload = self.parse_body()

        if not device_id:
            device_id = payload.get("device_id", "")

        status_code, resp = TelemetryProcessor.process_telemetry(device_id, token, payload)
        self.set_status(status_code)
        self.write(json.dumps(resp))


class ApiHeartbeatHandler(BaseApiHandler):
    def post(self):
        device_id = self.request.headers.get("X-Device-ID", "") or self.get_argument("device_id", "")
        token = self.get_auth_token()
        payload = self.parse_body()
        if not device_id:
            device_id = payload.get("device_id", "")

        status_code, resp = TelemetryProcessor.process_heartbeat(device_id, token)
        self.set_status(status_code)
        self.write(json.dumps(resp))


class ApiRemediationResultHandler(BaseApiHandler):
    def post(self):
        device_id = self.request.headers.get("X-Device-ID", "") or self.get_argument("device_id", "")
        token = self.get_auth_token()
        payload = self.parse_body()
        if not device_id:
            device_id = payload.get("device_id", "")

        status_code, resp = TelemetryProcessor.process_remediation_result(device_id, token, payload)
        self.set_status(status_code)
        self.write(json.dumps(resp))


class ApiHealthHandler(BaseApiHandler):
    def get(self):
        devices = _device_mgr.list_all_devices()
        self.write(json.dumps({
            "status": "healthy",
            "service": "AREE Multi-Device Platform",
            "version": "2.1.0",
            "enrolled_devices_count": len(devices),
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }))
