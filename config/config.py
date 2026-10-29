"""
AREE Configuration Loader
Loads default.yaml and environment variable overrides.
"""
import os
from pathlib import Path
from typing import Any, Dict
import yaml

DEFAULT_CONFIG_PATH = Path(__file__).parent / "default.yaml"

def load_config(config_path: str = None) -> Dict[str, Any]:
    """Load configuration from YAML file and apply env overrides."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    config: Dict[str, Any] = {}
    
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Failed to load config from {path}: {e}")
            config = {}

    # Defaults fallback if missing
    config.setdefault("monitoring", {})
    config["monitoring"].setdefault("interval_seconds", 10)
    config["monitoring"].setdefault("history_retention_hours", 24)

    config.setdefault("thresholds", {})
    config["thresholds"].setdefault("cpu_percent", 85.0)
    config["thresholds"].setdefault("ram_percent", 90.0)
    config["thresholds"].setdefault("disk_min_free_gb", 5.0)
    config["thresholds"].setdefault("process_cpu_percent", 80.0)
    config["thresholds"].setdefault("cooldown_seconds", 120)

    config.setdefault("risk", {})
    config["risk"].setdefault("warning_threshold", 45.0)
    config["risk"].setdefault("critical_threshold", 75.0)
    config["risk"].setdefault("default_bcs", 0.5)
    config["risk"].setdefault("weights", {
        "oss_risk": 0.35,
        "tes": 0.25,
        "dss": 0.25,
        "bcs": 0.15,
    })

    config.setdefault("remediation", {})
    config["remediation"].setdefault("mode", "SUGGEST")
    config["remediation"].setdefault("dry_run", True)
    config["remediation"].setdefault("configured_temp_dirs", [])
    config["remediation"].setdefault("registered_services", [])

    config.setdefault("notifications", {})
    config["notifications"].setdefault("slack_enabled", False)
    config["notifications"].setdefault("slack_channel", "#aree-alerts")
    config["notifications"].setdefault("re_alert_threshold", 75.0)

    config.setdefault("database", {})
    config["database"].setdefault("path", "aree_data.db")
    config["database"].setdefault("max_snapshot_rows", 1000)

    # Environment variable overrides
    if os.getenv("MONITORING_INTERVAL"):
        try:
            config["monitoring"]["interval_seconds"] = int(os.getenv("MONITORING_INTERVAL"))
        except ValueError:
            pass

    if os.getenv("MONITORING_MODE"):
        config["remediation"]["mode"] = os.getenv("MONITORING_MODE").upper()

    if os.getenv("SLACK_CHANNEL"):
        config["notifications"]["slack_channel"] = os.getenv("SLACK_CHANNEL")

    if os.getenv("RE_ALERT_THRESHOLD"):
        try:
            config["notifications"]["re_alert_threshold"] = float(os.getenv("RE_ALERT_THRESHOLD"))
        except ValueError:
            pass

    return config
