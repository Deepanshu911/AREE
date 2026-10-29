"""
store/db.py — Thread-safe SQLite persistence for incidents, metrics, and remediation logs.
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
    """Manages SQLite storage for operational metrics and incident lifecycles."""

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
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS metric_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    cpu_percent REAL NOT NULL,
                    ram_percent REAL NOT NULL,
                    data_source TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                )
                """)
                conn.commit()

    def save_incident(self, incident: Any) -> None:
        """Persist an incident to the database."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                ts = incident.timestamp.isoformat() if isinstance(incident.timestamp, datetime.datetime) else str(incident.timestamp)
                rule = getattr(incident.rule, "value", str(incident.rule))
                sev = getattr(incident.severity, "value", str(incident.severity))
                m_json = json.dumps(getattr(incident, "measurements", {}))
                cursor.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, timestamp, rule, severity, resource, value, threshold,
                    explanation, probable_cause, recommended_action, remediation_status, measurements_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    incident.incident_id, ts, rule, sev, incident.resource,
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

    def get_recent_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT * FROM incidents ORDER BY id DESC LIMIT ?
                """, (limit,))
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

    def save_snapshot(self, snapshot: Any) -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                ts = snapshot.timestamp.isoformat() if isinstance(snapshot.timestamp, datetime.datetime) else str(snapshot.timestamp)
                raw_dict = {
                    "cpu_per_core": getattr(snapshot, "cpu_per_core", []),
                    "ram_available_gb": getattr(snapshot, "ram_available_gb", 0),
                    "uptime_seconds": getattr(snapshot, "uptime_seconds", 0),
                    "net_bytes_sent_ps": getattr(snapshot, "net_bytes_sent_ps", 0),
                    "net_bytes_recv_ps": getattr(snapshot, "net_bytes_recv_ps", 0),
                }
                cursor.execute("""
                INSERT INTO metric_snapshots (timestamp, cpu_percent, ram_percent, data_source, raw_json)
                VALUES (?, ?, ?, ?, ?)
                """, (ts, snapshot.cpu_percent, snapshot.ram_percent, snapshot.data_source, json.dumps(raw_dict)))
                conn.commit()

    def get_metric_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT id, timestamp, cpu_percent, ram_percent, data_source, raw_json
                FROM metric_snapshots ORDER BY id DESC LIMIT ?
                """, (limit,))
                return [dict(r) for r in reversed(cursor.fetchall())]

    def save_remediation_log(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO remediation_log (
                    timestamp, incident_id, action, result, before_value, after_value, duration_seconds, operator
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
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

    def get_remediation_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT * FROM remediation_log ORDER BY id DESC LIMIT ?
                """, (limit,))
                return [dict(r) for r in cursor.fetchall()]
