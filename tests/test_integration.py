"""
tests/test_integration.py — End-to-end integration test of the monitoring and remediation lifecycle.
"""
from agent.collector import MetricCollector
from agent.detector import DetectionEngine, DetectionRule
from engine.risk import compute_oss, compute_re, classify_risk
from engine.remediation import PermissionMode, RemediationEngine
from store.db import IncidentDB

def test_full_pipeline_lifecycle(tmp_path):
    # 1. Initialize persistent DB
    db = IncidentDB(db_path=str(tmp_path / "integration.db"))

    # 2. Collect genuine metrics
    collector = MetricCollector()
    snapshot = collector.collect()
    assert snapshot.data_source == "live"
    db.save_snapshot(snapshot)

    # 3. Simulate high CPU & RAM condition and run detection
    snapshot.cpu_percent = 88.0
    snapshot.ram_percent = 96.5
    detector = DetectionEngine({"thresholds": {"ram_percent": 90.0, "cooldown_seconds": 0.0}})
    incidents = detector.detect(snapshot)
    assert len(incidents) >= 1
    for item in incidents:
        db.save_incident(item)

    # 4. Compute composite Risk Energy
    oss = compute_oss(cpu_pct=snapshot.cpu_percent, ram_pct=snapshot.ram_percent)
    re = compute_re(oss=oss, tes=0.4, dss=0.3, bcs=0.5)
    tier = classify_risk(re)
    assert re > 40.0  # Elevated due to 88% CPU, 96.5% RAM, threat, cascade

    # 5. Formulate and execute remediation for RAM incident
    ram_inc = next(i for i in incidents if i.rule == DetectionRule.HIGH_RAM)
    engine = RemediationEngine(mode=PermissionMode.APPROVED_AUTO)
    action_plan = engine.propose(ram_inc)
    assert action_plan.allowed is True

    result = engine.execute(action_plan, dry_run=False)
    assert "successfully executed" in result.result
    db.update_remediation_status(ram_inc.incident_id, "RESOLVED", result.result)

    # 6. Verify database records
    stored_incidents = db.get_recent_incidents()
    assert len(stored_incidents) >= 1
    matching = next(r for r in stored_incidents if r["incident_id"] == ram_inc.incident_id)
    assert matching["remediation_status"] == "RESOLVED"
