import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from datasource.base import DataSource, FlowRecord
from datasource.dataset_replay import DatasetReplaySource
from dashboard.api.server import app

client = TestClient(app)

def test_flow_record_to_alert_dict():
    rec = FlowRecord(
        timestamp=time.time(),
        src_ip="10.0.0.5",
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        attack_family="SYN_FLOOD",
        severity="CRITICAL",
        confidence=0.98,
        generator="scapy",
        features={"pkt_rate": 1500},
        explanation="SYN flood attack",
    )
    alert = rec.to_alert_dict()
    assert alert["threat_class"] == "SYN Flood"
    assert alert["severity"] == "CRITICAL"
    assert alert["confidence_score"] == 0.98
    assert alert["flow_id"]["src_ip"] == "10.0.0.5"
    assert alert["flow_id"]["dst_port"] == 80
    assert alert["_source"] == "dataset_replay"


def test_dataset_replay_lifecycle():
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data"))
    source = DatasetReplaySource(data_dir=data_dir, speed_factor=10.0)
    
    assert not source.is_running()
    source.start(scenario="random", duration=2.0)
    assert source.is_running()
    
    time.sleep(0.5)
    telem = source.read_telemetry()
    assert "pkts_per_sec" in telem
    assert "mbps" in telem
    assert "active_flows" in telem
    assert telem["status"] == "STREAMING"
    
    alerts = source.read_alerts(since_ts=0)
    assert isinstance(alerts, list)
    
    source.stop()
    assert not source.is_running()


def test_datasource_mode_api():
    # 1. GET datasource mode
    res = client.get("/api/datasource/mode")
    assert res.status_code == 200
    data = res.json()
    assert "mode" in data
    assert "dataset_available" in data
    assert data["dataset_available"] is True

    # 2. Switch mode to dataset
    res = client.post("/api/datasource/mode?mode=dataset")
    assert res.status_code == 200
    assert res.json()["mode"] == "dataset"

    # 3. Switch mode back to simulated
    res = client.post("/api/datasource/mode?mode=simulated")
    assert res.status_code == 200
    assert res.json()["mode"] == "simulated"

    # 4. Invalid mode error handling
    res = client.post("/api/datasource/mode?mode=invalid_mode")
    assert res.status_code == 400


def test_replay_api_dataset_mode():
    res = client.post("/api/replay?scenario=random&duration=2&mode=dataset")
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "dataset"
    assert data["dataset_available"] is True
    
    # Halting replay
    res_stop = client.post("/api/replay/stop")
    assert res_stop.status_code == 200
