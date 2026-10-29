"""
agent/watcher.py — Background thread monitoring supervisor.
"""
import datetime
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from agent.collector import MetricCollector, SystemSnapshot
from agent.detector import DetectionEngine, Incident
from store.db import IncidentDB

logger = logging.getLogger(__name__)

class MonitoringAgent:
    """Oversees background continuous telemetry collection and issue detection."""

    def __init__(self, config: Dict[str, Any], db: Optional[IncidentDB] = None):
        self.config = config
        self.interval = float(config.get("monitoring", {}).get("interval_seconds", 10))
        self.db = db or IncidentDB()

        self.collector = MetricCollector()
        self.detector = DetectionEngine(config)

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self._latest_snapshot: Optional[SystemSnapshot] = None
        self._recent_incidents: List[Incident] = []

    def start(self) -> None:
        """Start the background monitoring thread if not already running."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                logger.info("MonitoringAgent is already running.")
                return

            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run_loop, name="AREE-Watcher", daemon=True)
            self._thread.start()
            logger.info("MonitoringAgent background thread started (interval=%ss).", self.interval)

    def stop(self) -> None:
        """Signal background thread to stop and wait briefly for completion."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            logger.info("MonitoringAgent background thread stopped.")

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                snapshot = self.collector.collect()
                incidents = self.detector.detect(snapshot)

                with self._lock:
                    self._latest_snapshot = snapshot
                    if incidents:
                        self._recent_incidents = (incidents + self._recent_incidents)[:100]

                # Store snapshot & incidents in SQLite
                if self.db:
                    try:
                        self.db.save_snapshot(snapshot)
                        for inc in incidents:
                            self.db.save_incident(inc)
                    except Exception as db_err:
                        logger.error("Failed to save telemetry to DB: %s", db_err)

            except Exception as e:
                logger.error("Error in MonitoringAgent loop: %s", e)

            # Sleep in small slices so stop_event is responsive
            elapsed = 0.0
            while elapsed < self.interval and not self._stop_event.is_set():
                time.sleep(0.5)
                elapsed += 0.5

    def get_latest_snapshot(self) -> Optional[SystemSnapshot]:
        with self._lock:
            if self._latest_snapshot:
                return self._latest_snapshot
        # Fallback to immediate single collection if thread hasn't run yet
        try:
            snap = self.collector.collect()
            with self._lock:
                self._latest_snapshot = snap
            return snap
        except Exception:
            return None

    def get_recent_incidents(self, limit: int = 50) -> List[Incident]:
        with self._lock:
            if self._recent_incidents:
                return self._recent_incidents[:limit]
        if self.db:
            try:
                db_incidents = self.db.get_recent_incidents(limit=limit)
                return db_incidents
            except Exception:
                pass
        return []

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def is_healthy(self) -> bool:
        with self._lock:
            if not self._latest_snapshot:
                return False
            age = (datetime.datetime.utcnow() - self._latest_snapshot.timestamp).total_seconds()
            return age <= (self.interval * 3 + 5)
