# Unidirectional AI Threat Detector

An AI/ML pipeline designed to detect cyber threats on unidirectional (data diode / mirroring) tap links. Strict architectural constraints prevent any outward communication, enforcing read-only ingestion.

## Quick-Start Guide

### Prerequisites
- Python 3.9+
- `pip install -r requirements.txt` (or install manually: `scapy dpkt pydantic scikit-learn lightgbm torch pandas psutil fastapi uvicorn`)

### 1. Generate Synthetic Data
Run the traffic generators to produce the test dataset:
```bash
python tools/traffic_gen/syn_flood_gen.py
python tools/traffic_gen/c2_beacon_gen.py
python tools/traffic_gen/dns_tunnel_gen.py
python tools/traffic_gen/port_scan_gen.py
```

### 2. Feature Extraction & Training
Extract statistical features and train all ML models (LightGBM, Random Forest, Isolation Forest, OCSVM, etc.):
```bash
python models/train/dataset_generator.py
python models/train/ddos_train.py
python models/train/beaconing_train.py
python models/train/dga_train.py
python models/train/encrypted_train.py
python models/train/recon_train.py
python models/train/exfil_train.py
```

### 3. Start the Dashboard API
Launch the read-only FastAPI dashboard backend (serves on port 8000):
```bash
python -m uvicorn dashboard.api.server:app --port 8000
```

### 4. View Dashboard & Run Demo Replay
Open `http://localhost:8000` in your web browser. 
Click **"Start Live Demo Replay"** in the top right to simulate a live traffic feed and observe alerts streaming in!

## Architecture Constraints
- **Zero outbound TCP acks or probes**: The ingest module uses passive pcap parsing.
- **Incremental state**: Features use Welford's algorithm and HyperLogLog to bound memory usage.
- **Physical Gap Enforcement**: The dashboard reads only from a local SQLite sink; it cannot command the sensor.
