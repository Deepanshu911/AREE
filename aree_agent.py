#!/usr/bin/env python3
"""
aree_agent.py — Standalone launcher for the AREE Remote Monitoring Agent.
Install prerequisites: pip install psutil requests
Run: python aree_agent.py --server https://<your-streamlit-app> --enroll --name "My-Device"
"""
import sys, os
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.remote_agent import main

if __name__ == "__main__":
    main()
