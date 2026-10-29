"""
tests/test_collector.py — Unit tests for live metric collection.
"""
import datetime
from agent.collector import MetricCollector, SystemSnapshot

class TestMetricCollector:
    def test_collect_returns_valid_live_snapshot(self):
        collector = MetricCollector()
        snapshot = collector.collect()

        assert isinstance(snapshot, SystemSnapshot)
        assert snapshot.data_source == "live"
        assert 0.0 <= snapshot.cpu_percent <= 100.0
        assert 0.0 <= snapshot.ram_percent <= 100.0
        assert snapshot.ram_total_gb > 0.0
        assert snapshot.ram_available_gb >= 0.0
        assert snapshot.uptime_seconds >= 0.0

    def test_timestamp_is_fresh(self):
        collector = MetricCollector()
        snapshot = collector.collect()
        now = datetime.datetime.utcnow()
        age_seconds = abs((now - snapshot.timestamp).total_seconds())
        assert age_seconds < 5.0

    def test_disk_partitions_detected(self):
        collector = MetricCollector()
        snapshot = collector.collect()
        assert len(snapshot.disk_partitions) > 0
        for partition in snapshot.disk_partitions:
            assert partition.mountpoint
            assert partition.total_gb > 0.0
            assert 0.0 <= partition.percent_used <= 100.0

    def test_top_processes_structure(self):
        collector = MetricCollector()
        snapshot = collector.collect()
        assert isinstance(snapshot.top_processes, list)
        for proc in snapshot.top_processes:
            assert hasattr(proc, "pid")
            assert hasattr(proc, "name")
            assert hasattr(proc, "cpu_percent")
            assert hasattr(proc, "memory_percent")
