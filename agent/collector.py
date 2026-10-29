"""
agent/collector.py — Real-time psutil-based system metrics collector.
"""
from dataclasses import dataclass, field
import datetime
import logging
import time
from typing import Dict, List, Optional
import psutil

logger = logging.getLogger(__name__)

@dataclass
class ProcessInfo:
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    status: str

@dataclass
class DiskPartition:
    mountpoint: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent_used: float

@dataclass
class SystemSnapshot:
    timestamp: datetime.datetime
    data_source: str  # "live" | "mock" | "stale"
    cpu_percent: float
    cpu_per_core: List[float]
    ram_percent: float
    ram_available_gb: float
    ram_total_gb: float
    disk_partitions: List[DiskPartition]
    net_bytes_sent_ps: float
    net_bytes_recv_ps: float
    top_processes: List[ProcessInfo]
    uptime_seconds: float
    errors: List[str] = field(default_factory=list)

class MetricCollector:
    """Collects genuine system measurements safely across Windows, Linux, and macOS."""

    def __init__(self):
        self._last_net_io = None
        self._last_net_time = None
        # Warm up initial counters
        try:
            psutil.cpu_percent(interval=None)
            self._last_net_io = psutil.net_io_counters()
            self._last_net_time = time.time()
        except Exception as e:
            logger.warning("Collector initial warmup exception: %s", e)

    def collect(self) -> SystemSnapshot:
        errors: List[str] = []
        now = datetime.datetime.utcnow()

        # 1. CPU
        cpu_percent = 0.0
        cpu_per_core: List[float] = []
        try:
            cpu_percent = float(psutil.cpu_percent(interval=0.1))
            cpu_per_core = [float(c) for c in psutil.cpu_percent(interval=None, percpu=True)]
        except Exception as e:
            errors.append(f"CPU collection error: {e}")

        # 2. Memory
        ram_percent = 0.0
        ram_available_gb = 0.0
        ram_total_gb = 0.0
        try:
            mem = psutil.virtual_memory()
            ram_percent = float(mem.percent)
            ram_available_gb = round(mem.available / (1024 ** 3), 2)
            ram_total_gb = round(mem.total / (1024 ** 3), 2)
        except Exception as e:
            errors.append(f"Memory collection error: {e}")

        # 3. Disk Partitions
        disk_partitions: List[DiskPartition] = []
        try:
            partitions = psutil.disk_partitions(all=False)
            seen_mounts = set()
            for part in partitions:
                if part.mountpoint in seen_mounts:
                    continue
                seen_mounts.add(part.mountpoint)
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_partitions.append(
                        DiskPartition(
                            mountpoint=part.mountpoint,
                            total_gb=round(usage.total / (1024 ** 3), 2),
                            used_gb=round(usage.used / (1024 ** 3), 2),
                            free_gb=round(usage.free / (1024 ** 3), 2),
                            percent_used=float(usage.percent),
                        )
                    )
                except (PermissionError, psutil.AccessDenied):
                    continue
                except Exception:
                    continue
        except Exception as e:
            errors.append(f"Disk collection error: {e}")

        # 4. Network Bandwidth Rates
        net_bytes_sent_ps = 0.0
        net_bytes_recv_ps = 0.0
        try:
            current_net = psutil.net_io_counters()
            current_time = time.time()
            if self._last_net_io and self._last_net_time:
                time_diff = max(current_time - self._last_net_time, 0.001)
                net_bytes_sent_ps = max(0.0, (current_net.bytes_sent - self._last_net_io.bytes_sent) / time_diff)
                net_bytes_recv_ps = max(0.0, (current_net.bytes_recv - self._last_net_io.bytes_recv) / time_diff)
            self._last_net_io = current_net
            self._last_net_time = current_time
        except Exception as e:
            errors.append(f"Network rate error: {e}")

        # 5. Top Processes by CPU
        top_processes: List[ProcessInfo] = []
        try:
            proc_list = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
                try:
                    info = p.info
                    proc_list.append(
                        ProcessInfo(
                            pid=info.get("pid") or 0,
                            name=info.get("name") or "unknown",
                            cpu_percent=round(float(info.get("cpu_percent") or 0.0), 1),
                            memory_percent=round(float(info.get("memory_percent") or 0.0), 1),
                            status=info.get("status") or "unknown",
                        )
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            proc_list.sort(key=lambda x: x.cpu_percent, reverse=True)
            top_processes = proc_list[:10]
        except Exception as e:
            errors.append(f"Process list error: {e}")

        # 6. System Uptime
        uptime_seconds = 0.0
        try:
            uptime_seconds = max(0.0, time.time() - psutil.boot_time())
        except Exception as e:
            errors.append(f"Uptime collection error: {e}")

        return SystemSnapshot(
            timestamp=now,
            data_source="live",
            cpu_percent=cpu_percent,
            cpu_per_core=cpu_per_core,
            ram_percent=ram_percent,
            ram_available_gb=ram_available_gb,
            ram_total_gb=ram_total_gb,
            disk_partitions=disk_partitions,
            net_bytes_sent_ps=round(net_bytes_sent_ps, 1),
            net_bytes_recv_ps=round(net_bytes_recv_ps, 1),
            top_processes=top_processes,
            uptime_seconds=round(uptime_seconds, 1),
            errors=errors,
        )
