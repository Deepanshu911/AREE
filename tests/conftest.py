import datetime
import os
import sys
import pytest

# Ensure project root is in sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.collector import DiskPartition, ProcessInfo, SystemSnapshot

@pytest.fixture
def sample_snapshot():
    """Generates a predictable SystemSnapshot without psutil hardware calls."""
    return SystemSnapshot(
        timestamp=datetime.datetime.utcnow(),
        data_source="test",
        cpu_percent=45.0,
        cpu_per_core=[40.0, 50.0, 45.0, 45.0],
        ram_percent=62.0,
        ram_available_gb=6.0,
        ram_total_gb=16.0,
        disk_partitions=[
            DiskPartition(mountpoint="C:\\", total_gb=500.0, used_gb=250.0, free_gb=250.0, percent_used=50.0)
        ],
        net_bytes_sent_ps=2048.0,
        net_bytes_recv_ps=4096.0,
        top_processes=[
            ProcessInfo(pid=1001, name="python.exe", cpu_percent=25.0, memory_percent=3.5, status="running")
        ],
        uptime_seconds=3600.0,
    )

@pytest.fixture
def default_config():
    return {
        "thresholds": {
            "cpu_percent": 85.0,
            "ram_percent": 90.0,
            "disk_min_free_gb": 5.0,
            "process_cpu_percent": 80.0,
            "cooldown_seconds": 0.0,
        }
    }
