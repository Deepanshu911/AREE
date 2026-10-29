# ui/real_threats.py — AbuseIPDB threat feed (SECURE VERSION)
import os
import logging
import streamlit as st
import requests
import pandas as pd

logger = logging.getLogger(__name__)

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

@st.cache_data(ttl=300)
def fetch_live_threats(limit: int = 100) -> pd.DataFrame:
    """Fetch live malicious IPs from AbuseIPDB blacklist.
    Returns empty DataFrame if API key is not configured.
    """
    if not ABUSEIPDB_KEY:
        logger.warning("ABUSEIPDB_KEY not set — threat feed unavailable")
        return pd.DataFrame(columns=["ipAddress", "abuseConfidenceScore", "countryCode", "isp"])
    
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"confidenceMinimum": 90, "limit": limit}
    
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        return pd.DataFrame(data)
    except requests.exceptions.RequestException as e:
        logger.error("AbuseIPDB fetch failed: %s", e)
        return pd.DataFrame(columns=["ipAddress", "abuseConfidenceScore", "countryCode", "isp"])
