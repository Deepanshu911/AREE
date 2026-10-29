"""
agent/remote_agent.py — Lightweight, cross-platform remote telemetry and self-healing agent.
Runs on visitor computers (Windows / Linux / macOS) to transmit genuine local telemetry.
"""
import argparse
import datetime
import gc
import json
import logging
import os
from pathlib import Path
import platform
import socket
import sys
import time
from typing import Any, Dict, List, Optional
import psutil
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AREE-Agent")

CONFIG_FILE = Path("aree_agent_config.json")

class RemoteAgent:
    """Local monitoring client reporting genuine hardware telemetry to the AREE cloud server."""

    ALLOWLISTED_ACTIONS = {
        "GC_COLLECT",
        "CLEAR_TEMP_FILES",
        "LOWER_PROCESS_PRIORITY",
    }

    def __init__(
        self,
        server_url: str,
        device_id: Optional[str] = None,
        token: Optional[str] = None,
        device_name: Optional[str] = None,
        interval_seconds: int = 5,
        dry_run: bool = False,
    ):
        self.server_url = server_url.rstrip("/")
        self.device_id = device_id
        self.token = token
        self.device_name = device_name or socket.gethostname()
        self.interval = max(2, interval_seconds)
        self.dry_run = dry_run

        self._last_net_io = None
        self._last_net_time = None
        self._running = False

    def load_or_save_config(self) -> None:
        """Reads cached enrollment credentials if available."""
        if CONFIG_FILE.exists() and (not self.device_id or not self.token):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                    self.device_id = self.device_id or cached.get("device_id")
                    self.token = self.token or cached.get("token")
                    self.server_url = self.server_url or cached.get("server_url")
                    self.device_name = self.device_name or cached.get("device_name")
            except Exception as e:
                logger.warning("Could not read local config file: %s", e)

    def persist_credentials(self) -> None:
        """Persists enrollment tokens for seamless reconnection."""
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "server_url": self.server_url,
                    "device_id": self.device_id,
                    "token": self.token,
                    "device_name": self.device_name,
                }, f, indent=2)
            logger.info("Credentials saved to %s", CONFIG_FILE.resolve())
        except Exception as e:
            logger.warning("Failed saving local credentials: %s", e)

    def enroll(self) -> bool:
        """Enrolls this physical device with the deployed AREE server."""
        url = f"{self.server_url}/api/v1/devices/enroll"
        payload = {
            "device_name": self.device_name,
            "os_type": f"{platform.system()} {platform.release()}",
            "device_id": self.device_id,
            "metadata": {
                "hostname": socket.gethostname(),
                "cores_logical": psutil.cpu_count(logical=True),
                "cores_physical": psutil.cpu_count(logical=False),
                "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                "python_version": platform.python_version(),
            }
        }

        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code in (200, 201):
                data = resp.json()
                self.device_id = data["device_id"]
                self.token = data["token"]
                self.persist_credentials()
                logger.info("Successfully enrolled device: %s", self.device_id)
                return True
            else:
                logger.error("Enrollment failed (HTTP %s): %s", resp.status_code, resp.text)
                return False
        except Exception as e:
            logger.error("Connection error enrolling with %s: %s", url, e)
            return False

    def collect_local_telemetry(self) -> Dict[str, Any]:
        """Collects genuine local metrics using psutil."""
        now = datetime.datetime.utcnow().isoformat()

        # CPU
        cpu_pct = float(psutil.cpu_percent(interval=0.1))
        cpu_cores = [float(c) for c in psutil.cpu_percent(interval=None, percpu=True)]

        # Memory
        mem = psutil.virtual_memory()

        # Disk
        partitions = []
        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
                partitions.append({
                    "mountpoint": p.mountpoint,
                    "total_gb": round(u.total / (1024**3), 2),
                    "used_gb": round(u.used / (1024**3), 2),
                    "free_gb": round(u.free / (1024**3), 2),
                    "percent_used": float(u.percent),
                })
            except Exception:
                continue

        # Network rates
        net_sent = 0.0
        net_recv = 0.0
        try:
            curr_net = psutil.net_io_counters()
            curr_time = time.time()
            if self._last_net_io and self._last_net_time:
                dt = max(curr_time - self._last_net_time, 0.001)
                net_sent = max(0.0, (curr_net.bytes_sent - self._last_net_io.bytes_sent) / dt)
                net_recv = max(0.0, (curr_net.bytes_recv - self._last_net_io.bytes_recv) / dt)
            self._last_net_io = curr_net
            self._last_net_time = curr_time
        except Exception:
            pass

        # Top processes by CPU
        top_procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
            try:
                info = p.info
                top_procs.append({
                    "pid": info.get("pid") or 0,
                    "name": info.get("name") or "unknown",
                    "cpu_percent": round(float(info.get("cpu_percent") or 0.0), 1),
                    "memory_percent": round(float(info.get("memory_percent") or 0.0), 1),
                    "status": info.get("status") or "unknown",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        top_procs.sort(key=lambda x: x["cpu_percent"], reverse=True)

        uptime = max(0.0, time.time() - psutil.boot_time())

        return {
            "device_id": self.device_id,
            "timestamp": now,
            "cpu_percent": cpu_pct,
            "cpu_per_core": cpu_cores,
            "ram_percent": float(mem.percent),
            "ram_available_gb": round(mem.available / (1024**3), 2),
            "ram_total_gb": round(mem.total / (1024**3), 2),
            "disk_partitions": partitions,
            "net_bytes_sent_ps": round(net_sent, 1),
            "net_bytes_recv_ps": round(net_recv, 1),
            "top_processes": top_procs[:10],
            "uptime_seconds": round(uptime, 1),
            "threat_score": 0.05,
        }

    def execute_safe_remediation(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Safely executes only strictly allowlisted remediation tasks."""
        action_type = task.get("action_type")
        task_id = task.get("task_id")
        is_dry = bool(task.get("dry_run", self.dry_run))

        if action_type not in self.ALLOWLISTED_ACTIONS:
            return {
                "task_id": task_id,
                "result": f"Execution rejected by local agent: '{action_type}' is not on safe allowlist.",
                "before_value": None,
                "after_value": None,
            }

        start = time.time()
        before_ram = psutil.virtual_memory().percent
        result_msg = ""
        after_ram = before_ram

        if action_type == "GC_COLLECT":
            if is_dry:
                result_msg = "DRY-RUN: Would execute garbage collection on local Python runtimes."
            else:
                collected = gc.collect()
                after_ram = psutil.virtual_memory().percent
                result_msg = f"Executed gc.collect(). Freed {collected} objects. RAM now at {after_ram:.1f}%."

        elif action_type == "CLEAR_TEMP_FILES":
            temp_dir = os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp"
            if is_dry:
                result_msg = f"DRY-RUN: Would scan and purge safe tmp files in {temp_dir}."
            else:
                freed = 0
                count = 0
                try:
                    for f in os.listdir(temp_dir)[:40]:
                        fp = os.path.join(temp_dir, f)
                        if os.path.isfile(fp) and f.startswith("tmp"):
                            try:
                                sz = os.path.getsize(fp)
                                os.remove(fp)
                                freed += sz
                                count += 1
                            except Exception:
                                pass
                    result_msg = f"Cleaned {count} temporary files ({round(freed/(1024*1024), 2)} MB) in {temp_dir}."
                except Exception as e:
                    result_msg = f"Temp cleanup encountered error: {e}"

        elif action_type == "LOWER_PROCESS_PRIORITY":
            result_msg = "DRY-RUN: Process nice priority adjustment evaluated."

        return {
            "task_id": task_id,
            "incident_id": task.get("incident_id"),
            "action_type": action_type,
            "result": result_msg,
            "before_value": before_ram,
            "after_value": after_ram,
            "duration_seconds": round(time.time() - start, 3),
        }

    def start(self) -> None:
        """Starts reporting telemetry to the server."""
        self.load_or_save_config()

        if not self.device_id or not self.token:
            logger.info("Device is not enrolled. Attempting enrollment with %s...", self.server_url)
            if not self.enroll():
                logger.error("Could not enroll. Exiting.")
                return

        logger.info("Starting AREE Agent for %s (reporting every %ss to %s)",
                    self.device_id, self.interval, self.server_url)

        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Device-ID": self.device_id,
            "Content-Type": "application/json",
        }

        self._running = True
        consecutive_errors = 0

        while self._running:
            try:
                telemetry = self.collect_local_telemetry()
                resp = requests.post(
                    f"{self.server_url}/api/v1/devices/telemetry",
                    json=telemetry,
                    headers=headers,
                    timeout=8
                )

                if resp.status_code == 200:
                    data = resp.json()
                    consecutive_errors = 0
                    logger.info("Telemetry sent: CPU=%.1f%% RAM=%.1f%% → Server RE=%.1f",
                                telemetry["cpu_percent"], telemetry["ram_percent"], data.get("re_score", 0.0))

                    # Process any pending remediation tasks returned from server
                    for task in data.get("pending_tasks", []):
                        logger.info("Received remediation directive: %s (%s)", task.get("action_type"), task.get("task_id"))
                        report = self.execute_safe_remediation(task)
                        try:
                            requests.post(
                                f"{self.server_url}/api/v1/devices/remediate/result",
                                json=report,
                                headers=headers,
                                timeout=8
                            )
                            logger.info("Remediation execution outcome transmitted: %s", report.get("result"))
                        except Exception as post_err:
                            logger.error("Could not send remediation outcome: %s", post_err)

                elif resp.status_code == 401:
                    logger.error("Authentication failed. Token may be expired or invalid.")
                    time.sleep(10)
                else:
                    logger.warning("Telemetry rejected (HTTP %s): %s", resp.status_code, resp.text)
                    consecutive_errors += 1

            except requests.exceptions.RequestException as e:
                consecutive_errors += 1
                backoff = min(30, 2 ** min(consecutive_errors, 5))
                logger.warning("Network connection error to %s: %s (retrying in %ss)", self.server_url, e, backoff)
                time.sleep(backoff)
                continue
            except KeyboardInterrupt:
                logger.info("Stopping AREE Agent...")
                break
            except Exception as e:
                logger.error("Unexpected error in agent loop: %s", e)

            time.sleep(self.interval)

    def stop(self) -> None:
        self._running = False


def main():
    parser = argparse.ArgumentParser(description="AREE Remote Monitoring & Self-Healing Agent")
    parser.add_argument("--server", default="http://localhost:8501", help="URL of deployed AREE Streamlit app")
    parser.add_argument("--device-id", default=None, help="Assigned Device ID (if already enrolled)")
    parser.add_argument("--token", default=None, help="Device Auth Token (if already enrolled)")
    parser.add_argument("--name", default=None, help="Device friendly name (e.g. My-ThinkPad)")
    parser.add_argument("--interval", type=int, default=5, help="Telemetry reporting interval in seconds")
    parser.add_argument("--enroll", action="store_true", help="Force new device enrollment")
    parser.add_argument("--dry-run", action="store_true", help="Execute remediation in dry-run mode only")

    args = parser.parse_args()

    agent = RemoteAgent(
        server_url=args.server,
        device_id=args.device_id,
        token=args.token,
        device_name=args.name,
        interval_seconds=args.interval,
        dry_run=args.dry_run,
    )

    if args.enroll:
        if agent.enroll():
            print(f"\n✅ Device Enrolled Successfully!")
            print(f"Device ID: {agent.device_id}")
            print(f"Token:     {agent.token}\n")

    agent.start()

if __name__ == "__main__":
    main()
