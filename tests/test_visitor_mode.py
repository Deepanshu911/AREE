"""
tests/test_visitor_mode.py — Comprehensive tests for zero-install Visitor Mode,
session isolation, browser capability detection, and honest sandbox boundaries.
"""
import time
import pytest
from visitor.session import VisitorSession, generate_visitor_id, sanitize_str, validate_number


def test_visitor_session_auto_creation():
    """Verifies that visitor sessions auto-generate unique cryptographically random IDs and clean defaults."""
    session = VisitorSession()
    assert session.session_id.startswith("vis-")
    assert len(session.session_id) >= 12
    assert session.is_connected is True
    assert session.created_at is not None
    assert session.last_seen is not None


def test_two_visitors_receive_separate_isolated_sessions():
    """Verifies two different visitors get separate sessions with strict data isolation."""
    visitor_a = VisitorSession()
    visitor_b = VisitorSession()

    assert visitor_a.session_id != visitor_b.session_id

    # Visitor A reports macOS on MacBook
    success_a = visitor_a.update_from_client_payload({
        "browser": "Apple Safari",
        "os": "macOS 14 Sonoma",
        "cores": 8,
        "screen_width": 2560,
        "screen_height": 1600,
        "viewport_width": 1440,
        "viewport_height": 900,
        "online": True,
        "page_load_ms": 120.0,
    })
    assert success_a is True

    # Visitor B reports Windows on PC
    success_b = visitor_b.update_from_client_payload({
        "browser": "Google Chrome",
        "os": "Windows 11",
        "cores": 16,
        "screen_width": 1920,
        "screen_height": 1080,
        "viewport_width": 1920,
        "viewport_height": 1080,
        "online": True,
        "page_load_ms": 280.0,
    })
    assert success_b is True

    # Assert complete isolation between visitors
    assert visitor_a.os_name == "macOS 14 Sonoma"
    assert visitor_b.os_name == "Windows 11"

    assert visitor_a.logical_cores == 8
    assert visitor_b.logical_cores == 16

    assert visitor_a.screen_width == 2560
    assert visitor_b.screen_width == 1920

    assert visitor_a.page_load_ms == 120.0
    assert visitor_b.page_load_ms == 280.0


def test_unavailable_system_metrics_are_never_fabricated():
    """
    Verifies that host CPU %, RAM, disk space, and process tables are never fabricated
    and are clearly declared unavailable in the capability matrix.
    """
    visitor = VisitorSession()
    matrix = visitor.get_capability_matrix()
    assert len(matrix) >= 10

    matrix_by_metric = {row["metric"]: row for row in matrix}

    # Verify Host CPU is explicitly marked unavailable
    cpu_row = matrix_by_metric["Host CPU Utilization %"]
    assert "Not Available" in cpu_row["status"]
    assert "Unavailable" in cpu_row["value"]
    assert "sandbox" in cpu_row["boundary"].lower()

    # Verify Physical RAM is explicitly marked unavailable
    ram_row = matrix_by_metric["Physical RAM & Swap Usage"]
    assert "Not Available" in ram_row["status"]
    assert "Unavailable" in ram_row["value"]

    # Verify Storage is explicitly marked unavailable
    disk_row = matrix_by_metric["Local Disk Partitions & I/O"]
    assert "Not Available" in disk_row["status"]
    assert "Unavailable" in disk_row["value"]

    # Verify Processes are explicitly marked unavailable
    proc_row = matrix_by_metric["Running Operating System Processes"]
    assert "Not Available" in proc_row["status"]
    assert "Unavailable" in proc_row["value"]


def test_input_sanitization_and_xss_protection():
    """Ensures hostile or malformed browser payloads are sanitized to prevent XSS or memory bloat."""
    # XSS attempt
    cleaned_xss = sanitize_str("<script>alert('xss')</script>")
    assert "<script>" not in cleaned_xss
    assert "&lt;script&gt;" in cleaned_xss

    # Buffer inflation
    huge_str = "A" * 10000
    cleaned_huge = sanitize_str(huge_str, max_len=80)
    assert len(cleaned_huge) == 80

    # Bounds validation
    assert validate_number(8, min_val=1, max_val=256) == 8.0
    assert validate_number(-10, min_val=1, max_val=256) is None
    assert validate_number(500, min_val=1, max_val=256) is None
    assert validate_number("invalid_number") is None


def test_rate_limiting_protects_against_update_flooding():
    """Verifies that visitor telemetry updates are rate limited to prevent resource exhaustion."""
    visitor = VisitorSession()

    # First update succeeds
    first_res = visitor.update_from_client_payload({"cores": 4})
    assert first_res is True

    # Immediate second update within 0.1s is rate-limited
    rapid_res = visitor.update_from_client_payload({"cores": 8})
    assert rapid_res is False
    assert visitor.logical_cores == 4  # Unchanged due to rate limiting

    # Wait 0.6s and update again
    time.sleep(0.6)
    subsequent_res = visitor.update_from_client_payload({"cores": 8})
    assert subsequent_res is True
    assert visitor.logical_cores == 8
