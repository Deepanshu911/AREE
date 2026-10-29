"""
tests/test_remediation.py — Unit tests for safe remediation workflows and permission modes.
"""
import datetime
from agent.detector import DetectionRule, Incident, Severity
from engine.remediation import PermissionMode, RemediationEngine

class TestRemediationEngine:
    def test_observe_mode_denies_execution(self):
        engine = RemediationEngine(mode=PermissionMode.OBSERVE)
        inc = Incident(
            incident_id="test-obs",
            timestamp=datetime.datetime.utcnow(),
            rule=DetectionRule.HIGH_RAM,
            severity=Severity.HIGH,
            resource="Memory",
            value=94.0,
            threshold=90.0,
            explanation="Test RAM incident",
            probable_cause="Test",
            recommended_action="Free RAM",
        )
        plan = engine.propose(inc)
        assert plan.allowed is False
        assert "OBSERVE mode" in plan.reason

        executed = engine.execute(plan, dry_run=False)
        assert "Execution blocked" in executed.result

    def test_suggest_mode_requires_operator_dispatch(self):
        engine = RemediationEngine(mode=PermissionMode.SUGGEST)
        inc = Incident(
            incident_id="test-sug",
            timestamp=datetime.datetime.utcnow(),
            rule=DetectionRule.HIGH_RAM,
            severity=Severity.HIGH,
            resource="Memory",
            value=92.0,
            threshold=90.0,
            explanation="Test",
            probable_cause="Test",
            recommended_action="Test",
        )
        plan = engine.propose(inc)
        assert plan.allowed is False
        assert "SUGGEST mode" in plan.reason

    def test_approved_auto_mode_allows_safe_allowlist(self):
        engine = RemediationEngine(mode=PermissionMode.APPROVED_AUTO)
        inc = Incident(
            incident_id="test-auto",
            timestamp=datetime.datetime.utcnow(),
            rule=DetectionRule.HIGH_RAM,
            severity=Severity.HIGH,
            resource="Memory",
            value=93.0,
            threshold=90.0,
            explanation="Test",
            probable_cause="Test",
            recommended_action="Test",
        )
        plan = engine.propose(inc)
        assert plan.action_type == "GC_COLLECT"
        assert plan.allowed is True

    def test_dry_run_does_not_modify_state(self):
        engine = RemediationEngine(mode=PermissionMode.APPROVED_AUTO)
        inc = Incident(
            incident_id="test-dry",
            timestamp=datetime.datetime.utcnow(),
            rule=DetectionRule.HIGH_RAM,
            severity=Severity.HIGH,
            resource="Memory",
            value=93.0,
            threshold=90.0,
            explanation="Test",
            probable_cause="Test",
            recommended_action="Test",
        )
        plan = engine.propose(inc)
        result = engine.execute(plan, dry_run=True)
        assert "DRY-RUN:" in result.result

    def test_safe_gc_collect_execution(self):
        engine = RemediationEngine(mode=PermissionMode.APPROVED_AUTO)
        inc = Incident(
            incident_id="test-real",
            timestamp=datetime.datetime.utcnow(),
            rule=DetectionRule.HIGH_RAM,
            severity=Severity.HIGH,
            resource="Memory",
            value=93.0,
            threshold=90.0,
            explanation="Test",
            probable_cause="Test",
            recommended_action="Test",
        )
        plan = engine.propose(inc)
        result = engine.execute(plan, dry_run=False)
        assert "successfully executed" in result.result
        assert result.duration_seconds >= 0.0
