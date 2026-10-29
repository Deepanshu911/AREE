"""
store/db.py — Thread-safe SQLite persistence for multi-device telemetry, incidents, and remediation tasks.
"""
import datetime
import json
import logging
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class IncidentDB:
    """Manages SQLite storage for multi-device telemetry, incidents, and remediation."""

    def __init__(self, db_path: str = "aree_data.db"):
        self.db_path = str(Path(db_path).resolve())
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Devices registry table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    device_name TEXT NOT NULL,
                    os_type TEXT NOT NULL,
                    auth_token_hash TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """)

                # Multi-device incidents table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL DEFAULT 'local',
                    incident_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    value REAL NOT NULL,
                    threshold REAL NOT NULL,
                    explanation TEXT NOT NULL,
                    probable_cause TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    remediation_status TEXT NOT NULL,
                    measurements_json TEXT NOT NULL
                )
                """)

                # Multi-device remediation audit log
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL DEFAULT 'local',
                    timestamp TEXT NOT NULL,
                    incident_id TEXT,
                    action TEXT NOT NULL,
                    result TEXT,
                    before_value REAL,
                    after_value REAL,
                    duration_seconds REAL,
                    operator TEXT NOT NULL
                )
                """)

                # Multi-device metric snapshots
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS metric_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL DEFAULT 'local',
                    timestamp TEXT NOT NULL,
                    cpu_percent REAL NOT NULL,
                    ram_percent REAL NOT NULL,
                    data_source TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                )
                """)

                # Remote remediation task queue
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_tasks (
                    task_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    incident_id TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    dry_run INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    executed_at TEXT,
                    result TEXT,
                    before_value REAL,
                    after_value REAL
                )
                """)

                # Auto-migration for existing databases that lack device_id
                for table in ("incidents", "remediation_log", "metric_snapshots"):
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [row[1] for row in cursor.fetchall()]
                    if columns and "device_id" not in columns:
                        cursor.execute(f"ALTER TABLE {table} ADD COLUMN device_id TEXT NOT NULL DEFAULT 'local'")

                conn.commit()

    # ── Devices Management ────────────────────────────────────────────────────

    def register_device(self, device_id: str, device_name: str, os_type: str,
                        token_hash: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        now = datetime.datetime.utcnow().isoformat()
        meta_json = json.dumps(metadata or {})
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT OR REPLACE INTO devices (
                    device_id, device_name, os_type, auth_token_hash, registered_at, last_seen, status, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, 'connected', ?)
                """, (device_id, device_name, os_type, token_hash, now, now, meta_json))
                conn.commit()
        return self.get_device(device_id)

    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                item = dict(row)
                try:
                    item["metadata"] = json.loads(item["metadata_json"])
                except Exception:
                    item["metadata"] = {}
                return item

    def update_device_heartbeat(self, device_id: str, status: str = "connected") -> bool:
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                UPDATE devices SET last_seen = ?, status = ? WHERE device_id = ?
                """, (now, status, device_id))
                conn.commit()
                return cursor.rowcount > 0

    def list_devices(self, stale_seconds: float = 30.0, disconnect_seconds: float = 120.0) -> List[Dict[str, Any]]:
        """List all devices with dynamically calculated connection status."""
        now = datetime.datetime.utcnow()
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
                rows = cursor.fetchall()
                devices = []
                for r in rows:
                    d = dict(r)
                    try:
                        d["metadata"] = json.loads(d["metadata_json"])
                    except Exception:
                        d["metadata"] = {}

                    # Calculate dynamic status based on heartbeat age
                    try:
                        last_seen_dt = datetime.datetime.fromisoformat(d["last_seen"])
                        age = (now - last_seen_dt).total_seconds()
                        d["age_seconds"] = round(age, 1)
                        if age > disconnect_seconds:
                            d["connection_status"] = "disconnected"
                        elif age > stale_seconds:
                            d["connection_status"] = "stale"
                        else:
                            d["connection_status"] = "connected"
                    except Exception:
                        d["connection_status"] = d.get("status", "unknown")
                        d["age_seconds"] = 999999

                    devices.append(d)
                return devices

    # ── Incidents Management ──────────────────────────────────────────────────

    def save_incident(self, incident: Any, device_id: str = "local") -> None:
        """Persist an incident linked to a specific device."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                ts = incident.timestamp.isoformat() if isinstance(incident.timestamp, datetime.datetime) else str(incident.timestamp)
                rule = getattr(incident.rule, "value", str(incident.rule))
                sev = getattr(incident.severity, "value", str(incident.severity))
                m_json = json.dumps(getattr(incident, "measurements", {}))
                dev_id = getattr(incident, "device_id", device_id)
                cursor.execute("""
                INSERT OR REPLACE INTO incidents (
                    device_id, incident_id, timestamp, rule, severity, resource, value, threshold,
                    explanation, probable_cause, recommended_action, remediation_status, measurements_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    dev_id, incident.incident_id, ts, rule, sev, incident.resource,
                    incident.value, incident.threshold, incident.explanation,
                    incident.probable_cause, incident.recommended_action,
                    incident.remediation_status, m_json
                ))
                conn.commit()

    def update_remediation_status(self, incident_id: str, status: str, result: str = "") -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                UPDATE incidents
                SET remediation_status = ?, explanation = explanation || ' [Resolved: ' || ? || ']'
                WHERE incident_id = ?
                """, (status, result, incident_id))
                conn.commit()

    def get_recent_incidents(self, limit: int = 50, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if device_id:
                    cursor.execute("""
                    SELECT * FROM incidents WHERE device_id = ? ORDER BY id DESC LIMIT ?
                    """, (device_id, limit))
                else:
                    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
                rows = cursor.fetchall()
                results = []
                for r in rows:
                    item = dict(r)
                    try:
                        item["measurements"] = json.loads(item["measurements_json"])
                    except Exception:
                        item["measurements"] = {}
                    results.append(item)
                return results

    get_incidents = get_recent_incidents

    # ── Metric Snapshots ──────────────────────────────────────────────────────

    def save_snapshot(self, snapshot: Any, device_id: str = "local") -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                ts = snapshot.timestamp.isoformat() if isinstance(snapshot.timestamp, datetime.datetime) else str(snapshot.timestamp)
                raw_dict = {
                    "cpu_per_core": getattr(snapshot, "cpu_per_core", []),
                    "ram_available_gb": getattr(snapshot, "ram_available_gb", 0),
                    "ram_total_gb": getattr(snapshot, "ram_total_gb", 0),
                    "uptime_seconds": getattr(snapshot, "uptime_seconds", 0),
                    "net_bytes_sent_ps": getattr(snapshot, "net_bytes_sent_ps", 0),
                    "net_bytes_recv_ps": getattr(snapshot, "net_bytes_recv_ps", 0),
                    "disk_partitions": [
                        {
                            "mountpoint": getattr(p, "mountpoint", p.get("mountpoint") if isinstance(p, dict) else ""),
                            "total_gb": getattr(p, "total_gb", p.get("total_gb", 0) if isinstance(p, dict) else 0),
                            "used_gb": getattr(p, "used_gb", p.get("used_gb", 0) if isinstance(p, dict) else 0),
                            "free_gb": getattr(p, "free_gb", p.get("free_gb", 0) if isinstance(p, dict) else 0),
                            "percent_used": getattr(p, "percent_used", p.get("percent_used", 0) if isinstance(p, dict) else 0),
                        }
                        for p in getattr(snapshot, "disk_partitions", [])
                    ],
                    "top_processes": [
                        {
                            "pid": getattr(p, "pid", p.get("pid") if isinstance(p, dict) else 0),
                            "name": getattr(p, "name", p.get("name") if isinstance(p, dict) else ""),
                            "cpu_percent": getattr(p, "cpu_percent", p.get("cpu_percent", 0) if isinstance(p, dict) else 0),
                            "memory_percent": getattr(p, "memory_percent", p.get("memory_percent", 0) if isinstance(p, dict) else 0),
                            "status": getattr(p, "status", p.get("status") if isinstance(p, dict) else ""),
                        }
                        for p in getattr(snapshot, "top_processes", [])
                    ],
                }
                cursor.execute("""
                INSERT INTO metric_snapshots (device_id, timestamp, cpu_percent, ram_percent, data_source, raw_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (device_id, ts, snapshot.cpu_percent, snapshot.ram_percent, snapshot.data_source, json.dumps(raw_dict)))
                conn.commit()

    def get_latest_snapshot(self, device_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT * FROM metric_snapshots WHERE device_id = ? ORDER BY id DESC LIMIT 1
                """, (device_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                item = dict(row)
                try:
                    item["raw"] = json.loads(item["raw_json"])
                except Exception:
                    item["raw"] = {}
                return item

    def get_metric_history(self, limit: int = 100, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if device_id:
                    cursor.execute("""
                    SELECT id, device_id, timestamp, cpu_percent, ram_percent, data_source, raw_json
                    FROM metric_snapshots WHERE device_id = ? ORDER BY id DESC LIMIT ?
                    """, (device_id, limit))
                else:
                    cursor.execute("""
                    SELECT id, device_id, timestamp, cpu_percent, ram_percent, data_source, raw_json
                    FROM metric_snapshots ORDER BY id DESC LIMIT ?
                    """, (limit,))
                return [dict(r) for r in reversed(cursor.fetchall())]

    # ── Remediation Audit & Tasks ─────────────────────────────────────────────

    def save_remediation_log(self, entry: Dict[str, Any], device_id: str = "local") -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO remediation_log (
                    device_id, timestamp, incident_id, action, result, before_value, after_value, duration_seconds, operator
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.get("device_id", device_id),
                    entry.get("timestamp", datetime.datetime.utcnow().isoformat()),
                    entry.get("incident_id"),
                    entry.get("action", "UNKNOWN"),
                    entry.get("result", ""),
                    entry.get("before_value", 0.0),
                    entry.get("after_value", 0.0),
                    entry.get("duration_seconds", 0.0),
                    entry.get("operator", "AREE_AUTO"),
                ))
                conn.commit()

    def get_remediation_log(self, limit: int = 50, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if device_id:
                    cursor.execute("""
                    SELECT * FROM remediation_log WHERE device_id = ? ORDER BY id DESC LIMIT ?
                    """, (device_id, limit))
                else:
                    cursor.execute("SELECT * FROM remediation_log ORDER BY id DESC LIMIT ?", (limit,))
                return [dict(r) for r in cursor.fetchall()]

    def queue_remediation_task(self, task_id: str, device_id: str, action_type: str,
                               incident_id: str = None, dry_run: bool = True) -> None:
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO device_tasks (task_id, device_id, action_type, incident_id, status, dry_run, created_at)
                VALUES (?, ?, ?, ?, 'PENDING', ?, ?)
                """, (task_id, device_id, action_type, incident_id, 1 if dry_run else 0, now))
                conn.commit()

    def get_pending_tasks(self, device_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT * FROM device_tasks WHERE device_id = ? AND status = 'PENDING' ORDER BY created_at ASC
                """, (device_id,))
                return [dict(r) for r in cursor.fetchall()]

    def complete_task(self, task_id: str, result: str, before_val: float = None, after_val: float = None) -> None:
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                UPDATE device_tasks
                SET status = 'COMPLETED', executed_at = ?, result = ?, before_value = ?, after_value = ?
                WHERE task_id = ?
                """, (now, result, before_val, after_val, task_id))
                conn.commit()
