"""
agent/detector.py — Rule-based problem detection engine with transparent reasoning.
"""
from dataclasses import dataclass, field
import datetime
from enum import Enum
import time
from typing import Any, Dict, List, Optional
import uuid

from agent.collector import SystemSnapshot

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DetectionRule(str, Enum):
    HIGH_CPU = "HIGH_CPU"
    HIGH_RAM = "HIGH_RAM"
    LOW_DISK = "LOW_DISK"
    HIGH_PROCESS_CPU = "HIGH_PROCESS_CPU"
    NETWORK_ISSUE = "NETWORK_ISSUE"

@dataclass
class Incident:
    incident_id: str
    timestamp: datetime.datetime
    rule: DetectionRule
    severity: Severity
    resource: str
    value: float
    threshold: float
    explanation: str
    probable_cause: str
    recommended_action: str
    remediation_status: str = "PENDING"
    measurements: Dict[str, Any] = field(default_factory=dict)

class DetectionEngine:
    """Evaluates SystemSnapshot against configured operational thresholds with cooldowns."""

    def __init__(self, config: Dict[str, Any]):
        thresholds = config.get("thresholds", {}) if isinstance(config, dict) else {}
        self.cpu_threshold = float(thresholds.get("cpu_percent", config.get("cpu_threshold", 85.0)))
        self.ram_threshold = float(thresholds.get("ram_percent", config.get("ram_threshold", 90.0)))
        self.disk_min_free_gb = float(thresholds.get("disk_min_free_gb", config.get("disk_min_free_gb", 5.0)))
        self.process_cpu_threshold = float(thresholds.get("process_cpu_percent", config.get("process_cpu_threshold", 80.0)))
        self.cooldown_seconds = float(thresholds.get("cooldown_seconds", config.get("cooldown_seconds", 120.0)))

        self._cooldown_map: Dict[str, float] = {}

    def _is_cooling_down(self, key: str) -> bool:
        last_time = self._cooldown_map.get(key, 0.0)
        return (time.time() - last_time) < self.cooldown_seconds

    def _trigger_cooldown(self, key: str):
        self._cooldown_map[key] = time.time()

    def detect(self, snapshot: SystemSnapshot) -> List[Incident]:
        incidents: List[Incident] = []
        now = datetime.datetime.utcnow()

        # 1. High Overall CPU
        if snapshot.cpu_percent >= self.cpu_threshold:
            rule_key = f"{DetectionRule.HIGH_CPU}:system"
            if not self._is_cooling_down(rule_key):
                self._trigger_cooldown(rule_key)
                sev = Severity.CRITICAL if snapshot.cpu_percent >= 95.0 else Severity.HIGH
                incidents.append(
                    Incident(
                        incident_id=f"inc-cpu-{uuid.uuid4().hex[:8]}",
                        timestamp=now,
                        rule=DetectionRule.HIGH_CPU,
                        severity=sev,
                        resource="CPU",
                        value=round(snapshot.cpu_percent, 1),
                        threshold=self.cpu_threshold,
                        explanation=f"System CPU utilization is at {snapshot.cpu_percent:.1f}%, exceeding the configured {self.cpu_threshold:.1f}% threshold.",
                        probable_cause="Sustained background batch job, computational surge, runaway process, or compilation workload.",
                        recommended_action="Inspect top resource-consuming processes, lower process priority, or scale compute capacity.",
                        measurements={"cpu_percent": snapshot.cpu_percent, "per_core": snapshot.cpu_per_core},
                    )
                )

        # 2. High Overall RAM
        if snapshot.ram_percent >= self.ram_threshold:
            rule_key = f"{DetectionRule.HIGH_RAM}:system"
            if not self._is_cooling_down(rule_key):
                self._trigger_cooldown(rule_key)
                sev = Severity.CRITICAL if snapshot.ram_percent >= 96.0 else Severity.HIGH
                incidents.append(
                    Incident(
                        incident_id=f"inc-ram-{uuid.uuid4().hex[:8]}",
                        timestamp=now,
                        rule=DetectionRule.HIGH_RAM,
                        severity=sev,
                        resource="Memory",
                        value=round(snapshot.ram_percent, 1),
                        threshold=self.ram_threshold,
                        explanation=f"System memory usage is at {snapshot.ram_percent:.1f}%, with only {snapshot.ram_available_gb:.1f} GB available.",
                        probable_cause="Memory leak in running applications, oversized working sets, or insufficient RAM for concurrent applications.",
                        recommended_action="Trigger garbage collection on manageable runtimes, clear cached working sets, or restart memory-leaking services.",
                        measurements={"ram_percent": snapshot.ram_percent, "ram_available_gb": snapshot.ram_available_gb},
                    )
                )

        # 3. Low Disk Space
        for disk in snapshot.disk_partitions:
            if disk.free_gb < self.disk_min_free_gb or disk.percent_used >= 95.0:
                rule_key = f"{DetectionRule.LOW_DISK}:{disk.mountpoint}"
                if not self._is_cooling_down(rule_key):
                    self._trigger_cooldown(rule_key)
                    sev = Severity.CRITICAL if disk.free_gb < 2.0 else Severity.HIGH
                    incidents.append(
                        Incident(
                            incident_id=f"inc-disk-{uuid.uuid4().hex[:8]}",
                            timestamp=now,
                            rule=DetectionRule.LOW_DISK,
                            severity=sev,
                            resource=f"Disk ({disk.mountpoint})",
                            value=round(disk.free_gb, 1),
                            threshold=self.disk_min_free_gb,
                            explanation=f"Partition {disk.mountpoint} has only {disk.free_gb:.1f} GB free space remaining ({disk.percent_used:.1f}% used).",
                            probable_cause="Unbounded log growth, bloated temporary directories, accumulated docker caches, or download saturation.",
                            recommended_action="Execute temporary directory cleanup, rotate stale log files, or expand disk storage.",
                            measurements={"mountpoint": disk.mountpoint, "free_gb": disk.free_gb, "percent_used": disk.percent_used},
                        )
                    )

        # 4. Single Process Consuming Extreme CPU
        for proc in snapshot.top_processes[:3]:
            if proc.cpu_percent >= self.process_cpu_threshold:
                rule_key = f"{DetectionRule.HIGH_PROCESS_CPU}:{proc.pid}"
                if not self._is_cooling_down(rule_key):
                    self._trigger_cooldown(rule_key)
                    incidents.append(
                        Incident(
                            incident_id=f"inc-proc-{uuid.uuid4().hex[:8]}",
                            timestamp=now,
                            rule=DetectionRule.HIGH_PROCESS_CPU,
                            severity=Severity.HIGH,
                            resource=f"Process: {proc.name} (PID {proc.pid})",
                            value=round(proc.cpu_percent, 1),
                            threshold=self.process_cpu_threshold,
                            explanation=f"Process '{proc.name}' (PID: {proc.pid}) is consuming {proc.cpu_percent:.1f}% CPU independently.",
                            probable_cause="Infinite loop, unconstrained thread pool, or intense computing process.",
                            recommended_action="Check application logs, throttle process priority, or request authorization to terminate if unmanaged.",
                            measurements={"pid": proc.pid, "name": proc.name, "cpu_percent": proc.cpu_percent},
                        )
                    )

        return incidents
