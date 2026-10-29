#!/usr/bin/env python3
"""
monitor_batch.py — Batch monitoring runner for AREE.
Runs the monitoring agent for a single collection cycle and prints results.

Usage:
    python monitor_batch.py
"""
import sys
import os
import json
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    try:
        from agent.collector import MetricCollector
        collector = MetricCollector()
        snapshot = collector.collect()
        print(f"[{snapshot.timestamp}] CPU: {snapshot.cpu_percent:.1f}% | "
              f"RAM: {snapshot.ram_percent:.1f}% | "
              f"Source: {snapshot.data_source}")
        
        for disk in snapshot.disk_partitions:
            print(f"  Disk {disk.mountpoint}: {disk.percent_used:.1f}% used, "
                  f"{disk.free_gb:.1f} GB free")
        
        print(f"\nTop processes:")
        for proc in snapshot.top_processes[:5]:
            print(f"  {proc.name} (PID {proc.pid}): CPU {proc.cpu_percent:.1f}%")
            
    except ImportError:
        print("ERROR: agent/collector.py not found. Run from AREE root directory.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
