"""
chaos_test.py — Chaos testing harness for AREE risk and auto-remediation.
"""
import random
import sys, os
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.risk import compute_oss, compute_re, classify_risk
from engine.remediation import RemediationEngine, PermissionMode, RemediationAction
from agent.detector import Incident, DetectionRule, Severity

def chaos_inject():
    print("🚀 CHAOS TESTING AREE CANONICAL PIPELINE...")
    engine = RemediationEngine(mode=PermissionMode.APPROVED_AUTO)
    interventions = 0

    for i in range(10):
        cpu = random.uniform(20.0, 99.0)
        ram = random.uniform(30.0, 98.0)
        latency = random.uniform(200.0, 3000.0)

        oss = compute_oss(cpu_pct=cpu, ram_pct=ram, latency_ms=latency)
        tes = random.uniform(0.1, 0.9)
        dss = random.uniform(0.1, 0.7)
        re = compute_re(oss=oss, tes=tes, dss=dss, bcs=0.5)
        tier = classify_risk(re, warning=45.0, critical=75.0)

        print(f"SVC-{i:02d} [CPU={cpu:4.1f}% RAM={ram:4.1f}% Lat={latency:4.0f}ms] "
              f"→ OSS={oss:.2f} | RE={re:5.1f}% [{tier}]", end=" ")

        if tier == "CRITICAL":
            inc = Incident(
                incident_id=f"chaos-{i}",
                timestamp=__import__("datetime").datetime.utcnow(),
                rule=DetectionRule.HIGH_RAM if ram > cpu else DetectionRule.HIGH_CPU,
                severity=Severity.CRITICAL,
                resource=f"chaos-svc-{i}",
                value=re,
                threshold=75.0,
                explanation="Chaos injected risk threshold breach",
                probable_cause="Simulated stress spike",
                recommended_action="Execute allowlisted stabilization",
            )
            action = engine.propose(inc)
            result = engine.execute(action, dry_run=False)
            print(f"→ ⚡ AUTO-REMEDIATED ({result.action_type})")
            interventions += 1
        else:
            print("→ ✅ HEALTHY / MONITORED")

    print(f"\n🎯 Results: {interventions}/10 services mitigated. AREE Pipeline operational.")

if __name__ == "__main__":
    chaos_inject()
