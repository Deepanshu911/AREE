"""
tests/test_db.py — Unit tests for SQLite storage persistence.
"""
import datetime
from agent.detector import DetectionRule, Incident, Severity
from store.db import IncidentDB

class TestIncidentDB:
    def test_save_and_retrieve_incident(self, tmp_path):
        db_file = tmp_path / "test_aree.db"
        db = IncidentDB(db_path=str(db_file))

        inc = Incident(
            incident_id="inc-test-101",
            timestamp=datetime.datetime.utcnow(),
            rule=DetectionRule.HIGH_CPU,
            severity=Severity.HIGH,
            resource="CPU",
            value=89.5,
            threshold=85.0,
            explanation="Test incident explanation",
            probable_cause="Test cause",
            recommended_action="Test action",
            measurements={"cpu": 89.5},
        )
        db.save_incident(inc)

        recent = db.get_recent_incidents(limit=10)
        assert len(recent) == 1
        record = recent[0]
        assert record["incident_id"] == "inc-test-101"
        assert record["resource"] == "CPU"
        assert record["value"] == 89.5
        assert record["remediation_status"] == "PENDING"

    def test_update_remediation_status(self, tmp_path):
        db_file = tmp_path / "test_aree.db"
        db = IncidentDB(db_path=str(db_file))

        inc = Incident(
            incident_id="inc-test-102",
            timestamp=datetime.datetime.utcnow(),
            rule=DetectionRule.HIGH_RAM,
            severity=Severity.HIGH,
            resource="Memory",
            value=95.0,
            threshold=90.0,
            explanation="Test explanation",
            probable_cause="Test cause",
            recommended_action="Test action",
        )
        db.save_incident(inc)
        db.update_remediation_status("inc-test-102", "RESOLVED", "Garbage collection reclaimed 350MB")

        recent = db.get_recent_incidents(limit=10)
        assert recent[0]["remediation_status"] == "RESOLVED"
        assert "Resolved: Garbage collection" in recent[0]["explanation"]

    def test_save_and_retrieve_snapshot(self, tmp_path, sample_snapshot):
        db_file = tmp_path / "test_aree.db"
        db = IncidentDB(db_path=str(db_file))

        db.save_snapshot(sample_snapshot)
        history = db.get_metric_history(limit=10)
        assert len(history) == 1
        assert history[0]["cpu_percent"] == sample_snapshot.cpu_percent
        assert history[0]["ram_percent"] == sample_snapshot.ram_percent
