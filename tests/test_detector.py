"""
tests/test_detector.py — Unit tests for rule-based problem detection.
"""
from agent.detector import DetectionEngine, DetectionRule, Severity

class TestDetectionEngine:
    def test_healthy_snapshot_produces_no_incidents(self, sample_snapshot, default_config):
        engine = DetectionEngine(default_config)
        incidents = engine.detect(sample_snapshot)
        assert len(incidents) == 0

    def test_high_cpu_detection(self, sample_snapshot, default_config):
        sample_snapshot.cpu_percent = 92.5
        engine = DetectionEngine(default_config)
        incidents = engine.detect(sample_snapshot)

        rules = [i.rule for i in incidents]
        assert DetectionRule.HIGH_CPU in rules
        cpu_inc = next(i for i in incidents if i.rule == DetectionRule.HIGH_CPU)
        assert cpu_inc.value == 92.5
        assert cpu_inc.severity in (Severity.HIGH, Severity.CRITICAL)
        assert "CPU utilization" in cpu_inc.explanation
        assert cpu_inc.probable_cause

    def test_high_ram_detection(self, sample_snapshot, default_config):
        sample_snapshot.ram_percent = 94.0
        engine = DetectionEngine(default_config)
        incidents = engine.detect(sample_snapshot)

        rules = [i.rule for i in incidents]
        assert DetectionRule.HIGH_RAM in rules

    def test_low_disk_detection(self, sample_snapshot, default_config):
        sample_snapshot.disk_partitions[0].free_gb = 2.5
        sample_snapshot.disk_partitions[0].percent_used = 97.0
        engine = DetectionEngine(default_config)
        incidents = engine.detect(sample_snapshot)

        rules = [i.rule for i in incidents]
        assert DetectionRule.LOW_DISK in rules

    def test_cooldown_suppression(self, sample_snapshot, default_config):
        default_config["thresholds"]["cooldown_seconds"] = 60.0
        sample_snapshot.cpu_percent = 95.0

        engine = DetectionEngine(default_config)
        first_pass = engine.detect(sample_snapshot)
        second_pass = engine.detect(sample_snapshot)

        assert len(first_pass) == 1
        assert len(second_pass) == 0  # Cooled down
