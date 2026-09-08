import os
import sys
import json
import time
import asyncio
import threading
import subprocess
from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import StreamingResponse
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

def get_current_telemetry() -> Dict[str, Any]:
    """Returns real-time data diode ingestion throughput, bandwidth, flows, and latency metrics."""
    telemetry_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tests/telemetry.json'))
    if os.path.exists(telemetry_file):
        try:
            with open(telemetry_file, 'r') as f:
                data = json.load(f)
                if time.time() - data.get('updated_at', 0) < 15:
                    return data
        except Exception:
            pass

    # High-performance baseline optical tap emulation (simulating critical infrastructure link)
    import random
    jitter = random.uniform(0.96, 1.04)
    return {
        "pkts_per_sec": int(3600 * jitter),
        "mbps": round(24.8 * jitter, 1),
        "active_flows": int(164 * jitter),
        "latency_ms": round(1.18 * jitter, 2),
        "diode_mode": "PASSIVE RX ONLY (Tx Physically Disabled)",
        "status": "IDLE_BASELINE",
        "updated_at": time.time()
    }

@app.get("/api/stats/telemetry")
def get_telemetry():
    """Returns current passive link throughput, active flow counts, and processing latency."""
    return get_current_telemetry()

@app.get("/api/stream")
async def stream_live_events(request: Request):
    """
    Server-Sent Events (SSE) streaming endpoint.
    Pushes live telemetry and real-time alert events directly to the dashboard with sub-second latency.
    """
    async def event_generator():
        last_ts = time.time() - 3600
        sent_alert_ids = set()
        
        while True:
            if await request.is_disconnected():
                break

            # 1. Telemetry heartbeat (Throughput, Mbps, Flows, Latency)
            telem = get_current_telemetry()
            yield f"event: telemetry\ndata: {json.dumps(telem)}\n\n"

            # 2. Push any new alerts from the SQLite store with zero latency
            recent_alerts = store.read_alerts(start_time=last_ts)
            for a in recent_alerts:
                if a.alert_id not in sent_alert_ids:
                    sent_alert_ids.add(a.alert_id)
                    last_ts = max(last_ts, a.timestamp)
                    yield f"event: alert\ndata: {json.dumps(a.model_dump())}\n\n"

            await asyncio.sleep(0.8)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

current_replay_process: Optional[subprocess.Popen] = None
replay_lock = threading.Lock()

def stop_active_replay():
    """Recursively terminates any active background replay subprocess."""
    global current_replay_process
    with replay_lock:
        if current_replay_process and current_replay_process.poll() is None:
            try:
                import psutil
                p = psutil.Process(current_replay_process.pid)
                for child in p.children(recursive=True):
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass
                p.terminate()
                p.wait(timeout=1.0)
            except Exception:
                try:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(current_replay_process.pid)], capture_output=True)
                except Exception:
                    pass
            current_replay_process = None
            try:
                telemetry_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tests/telemetry.json'))
                if os.path.exists(telemetry_file):
                    with open(telemetry_file, 'w') as f:
                        json.dump({
                            "pkts_per_sec": 3600,
                            "mbps": 24.8,
                            "active_flows": 164,
                            "latency_ms": 1.18,
                            "diode_mode": "PASSIVE RX ONLY (Tx Physically Disabled)",
                            "status": "IDLE_BASELINE",
                            "updated_at": time.time()
                        }, f)
            except Exception:
                pass

def run_replay_script(scenario: str = "random", duration: Optional[float] = None):
    """Runs the phase 5 E2E test script in a background process with optional duration limit."""
    global current_replay_process
    stop_active_replay()
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tests/test_phase5_e2e.py'))
    cmd = [sys.executable, script_path, "--scenario", scenario]
    if duration and duration > 0:
        cmd += ["--duration", str(duration)]
    
    with replay_lock:
        current_replay_process = subprocess.Popen(cmd)
    current_replay_process.wait()

@app.post("/api/replay")
def trigger_replay(
    scenario: Optional[str] = Query("random"),
    duration: Optional[float] = Query(None)
):
    """
    Triggers a background simulation of the test dataset with dynamic threat variability.
    Supports customizable duration (e.g. 20s, 60s, 300s, 900s).
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
    thread = threading.Thread(target=run_replay_script, args=(scenario_clean, duration), daemon=True)
    thread.start()
    return {
        "status": "Replay started in background",
        "scenario": scenario_labels.get(scenario_clean, "Dynamic Random Mix"),
        "duration": duration
    }

@app.post("/api/replay/stop")
def stop_replay():
    """Immediately terminates the running live replay simulation."""
    stop_active_replay()
    summary_cache.invalidate()
    return {"status": "Replay stopped successfully"}

# Mount the static front-end app
app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../app'))
app.mount("/", StaticFiles(directory=app_dir, html=True), name="app")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
