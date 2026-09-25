import os
import sys
import json
import time
import asyncio
import threading
import subprocess
from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# Ensure alerting store can be imported without importing ingest
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from alerting.store import AlertStore

# Dataset Replay data source
try:
    from datasource.dataset_replay import DatasetReplaySource
    _DATASET_REPLAY_AVAILABLE = True
except ImportError:
    _DATASET_REPLAY_AVAILABLE = False
    DatasetReplaySource = None

# Production mode: Kafka + ClickHouse
PIPELINE_MODE = os.environ.get("PIPELINE_MODE", "local")  # "local" or "kafka"
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "kafka:9092")
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "9000"))

# Kafka live alert + telemetry queue (only used in kafka mode)
_kafka_alert_queue: "queue.Queue" = None  # populated in lifespan when PIPELINE_MODE=kafka
_kafka_telem_queue: "queue.Queue" = None

def _start_kafka_consumers():
    """Spawn background threads to consume alerts-normalized and telemetry Kafka topics."""
    import queue as _queue
    global _kafka_alert_queue, _kafka_telem_queue
    _kafka_alert_queue = _queue.Queue(maxsize=2000)
    _kafka_telem_queue = _queue.Queue(maxsize=100)

    def _consume(topic, q):
        try:
            from confluent_kafka import Consumer, KafkaError
            c = Consumer({
                "bootstrap.servers": KAFKA_BROKER,
                "group.id": f"dashboard-{topic}",
                "auto.offset.reset": "latest",
                "enable.auto.commit": True,
            })
            c.subscribe([topic])
            while True:
                msg = c.poll(timeout=0.1)
                if msg is None or msg.error(): continue
                try:
                    q.put_nowait(json.loads(msg.value()))
                except Exception:
                    pass
        except Exception as e:
            import logging; logging.getLogger("server").error(f"Kafka consumer ({topic}) error: {e}")

    threading.Thread(target=_consume, args=("alerts-normalized", _kafka_alert_queue), daemon=True).start()
    threading.Thread(target=_consume, args=("telemetry", _kafka_telem_queue), daemon=True).start()

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
    global store
    if PIPELINE_MODE == "kafka":
        # Production: use ClickHouse store + start Kafka consumers
        from alerting.clickhouse_store import ClickHouseAlertStore
        store = ClickHouseAlertStore(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT)
        _start_kafka_consumers()
        import logging; logging.getLogger("server").info("Running in KAFKA/ClickHouse mode.")
    else:
        # Local dev: use SQLite store
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
    # In kafka mode, pull the latest snapshot off the telemetry queue
    if PIPELINE_MODE == "kafka" and _kafka_telem_queue is not None:
        snap = None
        while not _kafka_telem_queue.empty():
            try: snap = _kafka_telem_queue.get_nowait()
            except Exception: break
        if snap:
            return snap
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

            # 1. Telemetry heartbeat
            if PIPELINE_MODE == "kafka" and _kafka_telem_queue is not None:
                snap = None
                while not _kafka_telem_queue.empty():
                    try: snap = _kafka_telem_queue.get_nowait()
                    except Exception: break
                telem = snap if snap else get_current_telemetry()
            elif _data_source_mode == "dataset" and _dataset_source is not None:
                telem = _dataset_source.read_telemetry()
            else:
                telem = get_current_telemetry()
            yield f"event: telemetry\ndata: {json.dumps(telem)}\n\n"

            # 2. Push new alerts
            if PIPELINE_MODE == "kafka" and _kafka_alert_queue is not None:
                # Drain Kafka alert queue into SSE stream
                drained = 0
                while not _kafka_alert_queue.empty() and drained < 50:
                    try:
                        alert_dict = _kafka_alert_queue.get_nowait()
                        alert_id = alert_dict.get("alert_id", "")
                        if alert_id and alert_id not in sent_alert_ids:
                            sent_alert_ids.add(alert_id)
                            yield f"event: alert\ndata: {json.dumps(alert_dict)}\n\n"
                        drained += 1
                    except Exception:
                        break
            elif _data_source_mode == "dataset" and _dataset_source is not None and _dataset_source.is_running():
                # Drain dataset replay alerts into SSE stream
                dataset_alerts = _dataset_source.read_alerts(since_ts=last_ts)
                yielded_alerts = 0
                for alert_dict in dataset_alerts:
                    alert_id = alert_dict.get("alert_id", "")
                    if alert_id and alert_id not in sent_alert_ids:
                        sent_alert_ids.add(alert_id)
                        last_ts = max(last_ts, alert_dict.get("timestamp", last_ts))
                        yield f"event: alert\ndata: {json.dumps(alert_dict)}\n\n"
                        yielded_alerts += 1
                        if yielded_alerts >= 50:
                            break
                if len(sent_alert_ids) > 10000:
                    sent_alert_ids = set(list(sent_alert_ids)[-5000:])
            else:
                # Only stream alerts when a simulation is actively running
                if current_replay_process is not None and current_replay_process.poll() is None:
                    recent_alerts = store.read_alerts(start_time=last_ts)
                    yielded_alerts = 0
                    for a in recent_alerts:
                        if a.alert_id not in sent_alert_ids:
                            sent_alert_ids.add(a.alert_id)
                            last_ts = max(last_ts, a.timestamp)
                            yield f"event: alert\ndata: {json.dumps(a.model_dump())}\n\n"
                            yielded_alerts += 1
                            if yielded_alerts >= 50:
                                break
                    if len(sent_alert_ids) > 10000:
                        sent_alert_ids = set(list(sent_alert_ids)[-5000:])
                else:
                    last_ts = time.time()

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

# ── Dataset replay source (singleton) ────────────────────────────────────────
_data_source_mode: str = "simulated"   # "simulated" | "dataset"
_dataset_source: Optional[Any] = None
_dataset_source_lock = threading.Lock()

def _get_or_create_dataset_source() -> Optional[Any]:
    """Lazily initialise DatasetReplaySource singleton."""
    global _dataset_source
    if not _DATASET_REPLAY_AVAILABLE:
        return None
    with _dataset_source_lock:
        if _dataset_source is None:
            data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data'))
            _dataset_source = DatasetReplaySource(data_dir=data_dir, speed_factor=1.0)
        return _dataset_source

def stop_active_replay():
    """Recursively terminates any active background replay subprocess or dataset source."""
    global current_replay_process
    # Stop dataset replay if running
    ds = _dataset_source
    if ds is not None and ds.is_running():
        ds.stop()
    with replay_lock:
        if current_replay_process and current_replay_process.poll() is None:
            pid = current_replay_process.pid
            try:
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
                else:
                    import psutil
                    p = psutil.Process(pid)
                    for child in p.children(recursive=True):
                        child.kill()
                    p.kill()
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

def run_replay_script(scenario: str = "random", duration: Optional[float] = None,
                      mode: str = "simulated"):
    """Runs either the E2E simulation or the dataset replay, based on `mode`."""
    global current_replay_process
    stop_active_replay()

    if mode == "dataset":
        ds = _get_or_create_dataset_source()
        if ds is None:
            import logging; logging.getLogger("server").warning("DatasetReplaySource not available.")
            return
        ds.start(scenario=scenario, duration=duration)
        # Block thread until dataset replay stops
        while ds.is_running():
            time.sleep(0.5)
    else:
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
    duration: Optional[float] = Query(None),
    mode: Optional[str] = Query(None)   # "simulated" | "dataset"
):
    """
    Triggers a background simulation or dataset replay.
    mode: "simulated" (default) | "dataset"
    """
    global _data_source_mode
    effective_mode = mode if mode in ("simulated", "dataset") else _data_source_mode
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
    thread = threading.Thread(
        target=run_replay_script,
        args=(scenario_clean, duration, effective_mode),
        daemon=True)
    thread.start()
    return {
        "status": "Replay started in background",
        "scenario": scenario_labels.get(scenario_clean, "Dynamic Random Mix"),
        "duration": duration,
        "mode": effective_mode,
        "dataset_available": _DATASET_REPLAY_AVAILABLE,
    }

@app.post("/api/replay/stop")
def stop_replay():
    """Immediately terminates the running live replay simulation."""
    stop_active_replay()
    summary_cache.invalidate()
    return {"status": "Replay stopped successfully"}


@app.get("/api/datasource/mode")
def get_datasource_mode():
    """Return the current data-source mode and availability."""
    ds = _dataset_source
    return {
        "mode": _data_source_mode,
        "simulated_running": current_replay_process is not None and current_replay_process.poll() is None,
        "dataset_running": ds is not None and ds.is_running(),
        "dataset_available": _DATASET_REPLAY_AVAILABLE,
    }


@app.post("/api/datasource/mode")
def set_datasource_mode(mode: str = Query(..., description="simulated | dataset")):
    """Switch data-source mode.  Stops any currently running replay."""
    global _data_source_mode
    if mode not in ("simulated", "dataset"):
        raise HTTPException(status_code=400, detail="mode must be 'simulated' or 'dataset'")
    if not _DATASET_REPLAY_AVAILABLE and mode == "dataset":
        raise HTTPException(status_code=503, detail="DatasetReplaySource not available — check datasource/ install")
    stop_active_replay()
    _data_source_mode = mode
    summary_cache.invalidate()
    return {"mode": _data_source_mode, "dataset_available": _DATASET_REPLAY_AVAILABLE}

# Mount the static front-end app
app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../app'))
app.mount("/", StaticFiles(directory=app_dir, html=True), name="app")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
