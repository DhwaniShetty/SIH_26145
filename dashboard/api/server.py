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

app = FastAPI(title="Threat-Detect Dashboard API")

# Enable CORS for local development/testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tests/test_alerts.db'))
store = AlertStore(db_path=db_path)

@app.get("/api/alerts")
def get_alerts(
    limit: int = 100, 
    offset: int = 0,
    detector: Optional[str] = None,
    severity: Optional[str] = None
):
    """Fetch paginated, filtered alerts. strictly read-only."""
    alerts = store.read_alerts(detector=detector, severity=severity)
    # Alerts are ordered by timestamp asc, let's reverse for dashboard (newest first)
    alerts.reverse()
    
    total = len(alerts)
    paginated = alerts[offset:offset+limit]
    
    return {
        "total": total,
        "alerts": [a.model_dump() for a in paginated]
    }

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    """Drill-down for a specific alert."""
    alerts = store.read_alerts()
    for a in alerts:
        if a.alert_id == alert_id:
            return a.model_dump()
    raise HTTPException(status_code=404, detail="Alert not found")

@app.get("/api/stats/summary")
def get_summary():
    """Summary stats for dashboard panels."""
    alerts = store.read_alerts()
    
    rate_by_class = {}
    top_talkers_counts = {}
    
    for a in alerts:
        # Alert Rate by Threat Class
        tc = a.threat_class
        rate_by_class[tc] = rate_by_class.get(tc, 0) + 1
        
        # Top talkers (Source IP)
        src = a.flow_id.src_ip
        if src:
            top_talkers_counts[src] = top_talkers_counts.get(src, 0) + 1
            
    # Sort top talkers
    top_talkers = [{"ip": k, "count": v} for k, v in sorted(top_talkers_counts.items(), key=lambda x: x[1], reverse=True)[:10]]
    
    return {
        "rate_by_class": rate_by_class,
        "top_talkers": top_talkers,
        "total_alerts": len(alerts)
    }

def run_replay_script():
    """Runs the phase 5 E2E test script in a background thread to simulate a live feed."""
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tests/test_phase5_e2e.py'))
    subprocess.run([sys.executable, script_path], check=False)

@app.post("/api/replay")
def trigger_replay():
    """
    Triggers a background simulation of the test dataset.
    This does NOT reach into the live ingest tap. It just runs a local script 
    that feeds synthetic pcaps into the store.
    """
    thread = threading.Thread(target=run_replay_script)
    thread.start()
    return {"status": "Replay started in background"}

# Mount the static front-end app
app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../app'))
app.mount("/", StaticFiles(directory=app_dir, html=True), name="app")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
