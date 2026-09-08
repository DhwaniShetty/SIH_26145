import os
import sys
import threading
import subprocess
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# Ensure alerting store can be imported without importing ingest
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from alerting.store import AlertStore

from contextlib import asynccontextmanager

import time

class SummaryCache:
    """Thread-safe in-memory cache for aggregate dashboard statistics with short TTL."""
    def __init__(self, ttl_seconds: float = 0.75):
        self.ttl = ttl_seconds
        self._last_time = 0.0
        self._cached_data = None
        self._lock = threading.Lock()

    def get_summary(self, store_instance: AlertStore) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            if self._cached_data is not None and (now - self._last_time) < self.ttl:
                return self._cached_data

            fresh_stats = store_instance.get_summary_stats()
            self._cached_data = fresh_stats
            self._last_time = now
            return fresh_stats

    def invalidate(self):
        with self._lock:
            self._cached_data = None
            self._last_time = 0.0

summary_cache = SummaryCache(ttl_seconds=0.75)

from alerting.schema import AlertRecord, FlowID, Evidence

def seed_baseline_alerts(store_target: AlertStore):
    """Inserts a small set of clean initial demo alerts in <2ms so dashboard renders immediately."""
    now = time.time()
    baseline = [
        AlertRecord(
            alert_id="init-alert-1",
            timestamp=now - 120,
            detector="ddos",
            threat_class="SYN Flood",
            severity="HIGH",
            confidence_score=0.92,
            flow_id=FlowID(src_ip="192.168.1.105", dst_ip="10.0.0.1", src_port=52341, dst_port=80, protocol="TCP"),
            evidence=Evidence(features={"syn_ratio": 15.2, "pkt_rate": 1200}, explanation="Volumetric SYN surge detected"),
            related_alert_ids=[]
        ),
        AlertRecord(
            alert_id="init-alert-2",
            timestamp=now - 80,
            detector="recon",
            threat_class="Port Scan",
            severity="MEDIUM",
            confidence_score=0.88,
            flow_id=FlowID(src_ip="192.168.1.110", dst_ip="10.0.0.1", src_port=44120, dst_port=443, protocol="TCP"),
            evidence=Evidence(features={"unique_dst_ports": 45}, explanation="Horizontal port reconnaissance detected"),
            related_alert_ids=[]
        ),
        AlertRecord(
            alert_id="init-alert-3",
            timestamp=now - 30,
            detector="beaconing",
            threat_class="C2 Beaconing",
            severity="HIGH",
            confidence_score=0.95,
            flow_id=FlowID(src_ip="192.168.1.115", dst_ip="185.220.101.5", src_port=49812, dst_port=8443, protocol="TCP"),
            evidence=Evidence(features={"jitter": 0.04, "interval_mean": 30.0}, explanation="Periodic C2 beaconing pattern identified"),
            related_alert_ids=[]
        ),
        AlertRecord(
            alert_id="init-alert-4",
            timestamp=now - 10,
            detector="dns_exfil",
            threat_class="DNS Tunneling",
            severity="CRITICAL",
            confidence_score=0.97,
            flow_id=FlowID(src_ip="192.168.1.120", dst_ip="8.8.8.8", src_port=53123, dst_port=53, protocol="UDP"),
            evidence=Evidence(features={"entropy": 4.6, "query_len": 48}, explanation="High-entropy encoded DNS query tunneling payload"),
            related_alert_ids=[]
        )
    ]
    store_target.append_batch(baseline)
    store_target.flush()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fast instant initialization without blocking the event loop
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tests/test_alerts.db'))
    store = AlertStore(db_path=db_path)
    store.clear()
    seed_baseline_alerts(store)
    summary_cache.invalidate()
    yield

app = FastAPI(title="Threat-Detect Dashboard API", lifespan=lifespan)

# Enable CORS for local development/testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_header(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tests/test_alerts.db'))
store = AlertStore(db_path=db_path)

@app.get("/api/alerts")
def get_alerts(
    limit: int = 100, 
    offset: int = 0,
    detector: Optional[str] = None,
    severity: Optional[str] = None
):
    """Fetch paginated, filtered alerts strictly read-only using SQL offsets/limits."""
    total, alerts = store.read_alerts_paginated(
        limit=limit,
        offset=offset,
        detector=detector,
        severity=severity
    )
    
    return {
        "total": total,
        "alerts": [a.model_dump() for a in alerts]
    }

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    """Drill-down for a specific alert via direct O(1) index lookup."""
    alert = store.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.model_dump()

@app.get("/api/stats/summary")
def get_summary():
    """Summary stats for dashboard panels, served with sub-millisecond in-memory caching."""
    return summary_cache.get_summary(store)

def run_replay_script(scenario: str = "random"):
    """Runs the phase 5 E2E test script in a background thread to simulate a live feed."""
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tests/test_phase5_e2e.py'))
    cmd = [sys.executable, script_path, "--scenario", scenario]
    subprocess.run(cmd, check=False)

@app.post("/api/replay")
def trigger_replay(scenario: Optional[str] = Query("random")):
    """
    Triggers a background simulation of the test dataset with dynamic threat variability.
    Supports random, massive_ddos, stealth_c2_exfil, recon_storm, quiet_hours, coordinated_campaign.
    """
    scenario_clean = scenario if scenario in ["random", "massive_ddos", "stealth_c2_exfil", "recon_storm", "quiet_hours", "coordinated_campaign"] else "random"
    
    scenario_labels = {
        "random": "Dynamic Random Attack Mix",
        "massive_ddos": "Massive Volumetric DDoS (Thousands of alerts)",
        "stealth_c2_exfil": "Stealthy C2 & DNS Exfil (0 DDoS)",
        "recon_storm": "Reconnaissance Scan Storm (0 DDoS, 0 C2)",
        "quiet_hours": "Calm Baseline (Low Threat)",
        "coordinated_campaign": "Coordinated Multi-Vector Wave"
    }
    
    summary_cache.invalidate()
    thread = threading.Thread(target=run_replay_script, args=(scenario_clean,), daemon=True)
    thread.start()
    return {
        "status": "Replay started in background",
        "scenario": scenario_labels.get(scenario_clean, "Dynamic Random Mix")
    }

# Mount the static front-end app
app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../app'))
app.mount("/", StaticFiles(directory=app_dir, html=True), name="app")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
