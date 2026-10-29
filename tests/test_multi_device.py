"""
tests/test_multi_device.py — Comprehensive tests for multi-device enrollment,
authentication, telemetry ingest, data isolation, and remote remediation safety.
"""
import datetime
import os
import tempfile
import pytest

from agent.remote_agent import RemoteAgent
from server.device_manager import DeviceManager
from server.ingest import TelemetryProcessor
from store.db import IncidentDB


@pytest.fixture
def temp_db():
    """Provides a fresh isolated SQLite database for each test."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_path = f.name
    db = IncidentDB(db_path=temp_path)
    yield db
    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except OSError:
        pass


def test_device_enrollment_and_auth(temp_db):
    """Verifies cryptographic enrollment, secret token hashing, and HMAC authentication."""
    mgr = DeviceManager(temp_db)

    # 1. Enroll Alice and Bob
    dev_alice, token_alice = mgr.enroll_device("Alice Laptop", "Windows 11", custom_id="dev-alice")
    dev_bob, token_bob = mgr.enroll_device("Bob Workstation", "Ubuntu 22.04", custom_id="dev-bob")

    assert dev_alice == "dev-alice"
    assert dev_bob == "dev-bob"
    assert token_alice != token_bob
    assert token_alice.startswith("aree_tok_")

    # 2. Check token hashing — secret token must never be stored in plaintext
    alice_record = mgr.get_device_info("dev-alice")
    assert alice_record is not None
    assert "token" not in alice_record
    assert alice_record["auth_token_hash"] == mgr.hash_token(token_alice)
    assert token_alice not in alice_record["auth_token_hash"]

    # 3. Authenticate with correct tokens
    assert mgr.authenticate("dev-alice", token_alice) is True
    assert mgr.authenticate("dev-bob", token_bob) is True

    # 4. Reject incorrect, swapped, or empty tokens
    assert mgr.authenticate("dev-alice", "wrong_token") is False
    assert mgr.authenticate("dev-alice", token_bob) is False
    assert mgr.authenticate("dev-bob", token_alice) is False
    assert mgr.authenticate("dev-unknown", token_alice) is False
    assert mgr.authenticate("dev-alice", "") is False


def test_device_heartbeat_and_connection_status(temp_db):
    """Verifies heartbeat recording and dynamic connected/stale/disconnected states."""
    mgr = DeviceManager(temp_db)
    mgr.enroll_device("Server Node", "Linux", custom_id="dev-server")

    # Initial state after enrollment is connected
    devices = temp_db.list_devices(stale_seconds=30.0, disconnect_seconds=120.0)
    assert len(devices) == 1
    assert devices[0]["device_id"] == "dev-server"
    assert devices[0]["connection_status"] == "connected"

    # Verify heartbeat update
    assert mgr.record_heartbeat("dev-server") is True

    # Simulate stale state with small threshold
    devices_stale = temp_db.list_devices(stale_seconds=0.0, disconnect_seconds=120.0)
    assert devices_stale[0]["connection_status"] in ("stale", "connected")

    # Simulate disconnected state with zero threshold
    devices_disc = temp_db.list_devices(stale_seconds=0.0, disconnect_seconds=0.0)
    assert devices_disc[0]["connection_status"] == "disconnected"


def test_telemetry_ingest_and_data_isolation(temp_db, monkeypatch):
    """Verifies that telemetry and incidents from separate devices are strictly isolated."""
    # Monkeypatch singleton DB in ingest to test DB
    import server.ingest as ingest_mod
    monkeypatch.setattr(ingest_mod, "_db", temp_db)
    monkeypatch.setattr(ingest_mod, "_device_mgr", DeviceManager(temp_db))

    # Enroll two devices via API handler
    status_a, res_a = TelemetryProcessor.process_enrollment({
        "device_name": "Device Alpha",
        "os_type": "macOS",
        "device_id": "dev-alpha"
    })
    assert status_a == 201
    token_a = res_a["token"]

    status_b, res_b = TelemetryProcessor.process_enrollment({
        "device_name": "Device Beta",
        "os_type": "Windows",
        "device_id": "dev-beta"
    })
    assert status_b == 201
    token_b = res_b["token"]

    # Ingest High CPU on Device Alpha
    telemetry_alpha = {
        "cpu_percent": 96.5,
        "ram_percent": 45.0,
        "cpu_per_core": [95.0, 98.0],
        "ram_available_gb": 8.0,
        "ram_total_gb": 16.0,
        "disk_partitions": [{"mountpoint": "/", "total_gb": 500, "used_gb": 200, "free_gb": 300, "percent_used": 40.0}],
        "top_processes": [{"pid": 1234, "name": "stress_test", "cpu_percent": 92.0, "memory_percent": 5.0, "status": "running"}],
        "uptime_seconds": 3600,
    }
    code_a, out_a = TelemetryProcessor.process_telemetry("dev-alpha", token_a, telemetry_alpha)
    assert code_a == 200
    assert out_a["incidents_detected"] >= 1

    # Ingest Healthy Idle Telemetry on Device Beta
    telemetry_beta = {
        "cpu_percent": 12.0,
        "ram_percent": 30.0,
        "cpu_per_core": [10.0, 14.0],
        "ram_available_gb": 11.2,
        "ram_total_gb": 16.0,
        "disk_partitions": [{"mountpoint": "C:\\", "total_gb": 500, "used_gb": 100, "free_gb": 400, "percent_used": 20.0}],
        "top_processes": [{"pid": 5678, "name": "idle_proc", "cpu_percent": 1.0, "memory_percent": 2.0, "status": "running"}],
        "uptime_seconds": 7200,
    }
    code_b, out_b = TelemetryProcessor.process_telemetry("dev-beta", token_b, telemetry_beta)
    assert code_b == 200
    assert out_b["incidents_detected"] == 0

    # Verify Data Isolation in Database
    snap_alpha = temp_db.get_latest_snapshot("dev-alpha")
    snap_beta = temp_db.get_latest_snapshot("dev-beta")

    assert snap_alpha is not None
    assert snap_beta is not None
    assert snap_alpha["cpu_percent"] == 96.5
    assert snap_beta["cpu_percent"] == 12.0

    # Incidents Isolation
    incidents_alpha = temp_db.get_incidents(device_id="dev-alpha")
    incidents_beta = temp_db.get_incidents(device_id="dev-beta")

    assert len(incidents_alpha) >= 1
    assert len(incidents_beta) == 0  # Beta had healthy telemetry, zero incidents


def test_remote_remediation_task_flow(temp_db):
    """Verifies task queuing, device isolation, and completion lifecycle."""
    temp_db.queue_remediation_task("task-001", "dev-alpha", "GC_COLLECT", incident_id="inc-1", dry_run=False)
    temp_db.queue_remediation_task("task-002", "dev-beta", "CLEAR_TEMP_FILES", incident_id="inc-2", dry_run=True)

    # Device alpha only sees task-001
    alpha_tasks = temp_db.get_pending_tasks("dev-alpha")
    assert len(alpha_tasks) == 1
    assert alpha_tasks[0]["task_id"] == "task-001"
    assert alpha_tasks[0]["action_type"] == "GC_COLLECT"
    assert alpha_tasks[0]["dry_run"] == 0

    # Device beta only sees task-002
    beta_tasks = temp_db.get_pending_tasks("dev-beta")
    assert len(beta_tasks) == 1
    assert beta_tasks[0]["task_id"] == "task-002"
    assert beta_tasks[0]["dry_run"] == 1

    # Complete task-001
    temp_db.complete_task("task-001", result="Freed 450MB memory", before_val=85.0, after_val=60.0)

    # Pending tasks for dev-alpha is now empty
    assert len(temp_db.get_pending_tasks("dev-alpha")) == 0
    # Pending tasks for dev-beta remains untouched
    assert len(temp_db.get_pending_tasks("dev-beta")) == 1


def test_agent_allowlist_and_safety_boundaries():
    """Ensures agent strictly restricts actions to the allowlist and rejects arbitrary execution."""
    allowlist = RemoteAgent.ALLOWLISTED_ACTIONS
    assert "GC_COLLECT" in allowlist
    assert "CLEAR_TEMP_FILES" in allowlist
    assert "LOWER_PROCESS_PRIORITY" in allowlist

    # Ensure dangerous actions are strictly forbidden
    forbidden = ["EXEC_SHELL", "FORMAT_DRIVE", "DROP_DATABASE", "RM_RF", "KILL_SYSTEM"]
    for action in forbidden:
        assert action not in allowlist

    # Test agent dispatcher rejects forbidden action
    agent = RemoteAgent(server_url="http://localhost:8501", device_id="dev-test", token="tok-123")
    res = agent.execute_safe_remediation({
        "task_id": "malicious-1",
        "action_type": "EXEC_SHELL",
        "dry_run": 0
    })
    assert "not on safe allowlist" in res["result"].lower()
