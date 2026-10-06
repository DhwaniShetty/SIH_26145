# Sentrix — Unidirectional AI Threat Detector

> **Smart India Hackathon 2025 · Problem Statement 26145**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Rust](https://img.shields.io/badge/Rust-1.78%2B-CE422B?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![ONNX](https://img.shields.io/badge/ONNX-Runtime-005CED?logo=onnx&logoColor=white)](https://onnxruntime.ai)
[![Kafka](https://img.shields.io/badge/Apache-Kafka-231F20?logo=apachekafka&logoColor=white)](https://kafka.apache.org)
[![ClickHouse](https://img.shields.io/badge/ClickHouse-24.3-FFCC01?logo=clickhouse&logoColor=black)](https://clickhouse.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

An end-to-end AI/ML pipeline for detecting cyber threats on **unidirectional network taps** (data diodes / port mirrors). Strict architectural constraints guarantee **zero outbound communication** — the sensor reads traffic but can never write back to the monitored segment.

```
  Monitored Network
  ─────────────────
       │  (one-way tap / data diode)
       ▼
  ┌──────────┐    Kafka     ┌───────────┐    ClickHouse   ┌───────────┐
  │  Rust    │─raw-features→│  Python   │──alerts-norm'd──→│ FastAPI   │
  │ Ingestor │              │  ONNX     │                  │ Dashboard │
  │ 50k PPS  │              │ Inference │                  │  + SSE    │
  └──────────┘              └───────────┘                  └───────────┘
```

---

## ✨ Highlights

| Capability | Detail |
|---|---|
| **Throughput** | Rust ingestor handles **50 000 PPS** with zero packet loss |
| **Latency** | End-to-end alert latency < **100 ms** at full load |
| **Threat coverage** | 7 ML detectors covering DDoS, beaconing, DGA, DNS tunnelling, exfiltration, encrypted traffic & recon |
| **Inference engine** | All models compiled to **ONNX** for accelerated, runtime-agnostic scoring |
| **Storage** | **ClickHouse** columnar store for high-speed alert ingestion and historical queries |
| **Transport** | **Apache Kafka** decouples ingestor, inference workers, and dashboard |
| **Zero-outbound** | Passive PCAP parsing only — no TCP ACKs, no probes, no callbacks |
| **Memory efficiency** | Welford's online algorithm + HyperLogLog bound memory per flow |
| **Demo mode** | One-click live replay with pre-labeled dataset streaming |

---

## 📐 Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         SENTRIX PIPELINE                        │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  INGEST LAYER                                            │   │
│  │  ingest/rust-ingestor/   — Rust, libpcap, 50k PPS       │   │
│  │  ingest/pcap_reader.py   — Python fallback               │   │
│  │  ingest/zeek_reader.py   — Zeek log reader               │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│                               │  raw-features (Kafka topic)     │
│  ┌────────────────────────────▼─────────────────────────────┐   │
│  │  FEATURE LAYER                                           │   │
│  │  features/ddos_features.py       — volumetric stats      │   │
│  │  features/beaconing_features.py  — Welford IAT           │   │
│  │  features/dga_dns_features.py    — entropy / n-gram      │   │
│  │  features/dns_exfil_features.py  — query-length dist.    │   │
│  │  features/encrypted_meta_features.py                     │   │
│  │  features/recon_scan_features.py — port spread / sweep   │   │
│  │  features/exfiltration_features.py                       │   │
│  │  features/online_stats.py        — HyperLogLog, Welford  │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│                               │                                 │
│  ┌────────────────────────────▼─────────────────────────────┐   │
│  │  INFERENCE LAYER                                         │   │
│  │  inference/worker.py      — Kafka consumer, orchestrator │   │
│  │  inference/onnx_engine.py — ONNX Runtime scorer          │   │
│  │  inference/export_onnx.py — sklearn/LightGBM → ONNX      │   │
│  │  models/                  — per-threat detectors         │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│                               │  alerts-normalized (Kafka)      │
│  ┌────────────────────────────▼─────────────────────────────┐   │
│  │  ALERTING LAYER                                          │   │
│  │  alerting/store.py          — ClickHouse + SQLite sink   │   │
│  │  alerting/correlator.py     — multi-signal correlation   │   │
│  │  alerting/normalizer.py     — severity normalisation     │   │
│  │  alerting/calibration.py    — Platt/isotonic calibration │   │
│  │  alerting/webhook.py        — outbound webhook relay     │   │
│  └────────────────────────────┬─────────────────────────────┘   │
│                               │                                 │
│  ┌────────────────────────────▼─────────────────────────────┐   │
│  │  DASHBOARD LAYER                                         │   │
│  │  dashboard/api/server.py — FastAPI REST + SSE            │   │
│  │  dashboard/app/          — Web UI (charts, alerts table) │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Kafka Topics

| Topic | Partitions | Retention | Purpose |
|---|---|---|---|
| `raw-features` | 8 | 60 s | Ingestor → Inference |
| `alerts-normalized` | 4 | 1 h | Inference → Dashboard / ClickHouse |
| `telemetry` | 1 | 60 s | System health metrics |

### Physical Gap Enforcement

The dashboard **reads from ClickHouse only**. It cannot send any command back to the sensor or to the monitored network. This is enforced by:

1. Passive PCAP parsing (no `libpcap` injection mode)
2. No writable socket to the monitored interface
3. Dashboard runs in a separate Docker network segment with no route to the sensor NIC

---

## 🧠 ML Detectors

| Detector | Model(s) | Key Features | Threat |
|---|---|---|---|
| `ddos_detector` | LightGBM + Isolation Forest | PPS, BPS, SYN ratio, burst score | DDoS / SYN flood / UDP amplification |
| `beaconing_detector` | Random Forest + OCSVM | IAT mean/std, Welford δ, connection periodicity | C2 Beaconing |
| `dga_classifier` | LightGBM | Character n-gram entropy, vowel ratio, length dist. | DGA domains |
| `dns_exfil_detector` | Random Forest | Query length distribution, subdomain depth, entropy | DNS exfiltration / tunnelling |
| `encrypted_traffic_classifier` | LightGBM | TLS metadata, packet-size entropy, burst timing | Encrypted C2 / covert channel |
| `recon_scan_detector` | Isolation Forest | Port spread, destination diversity, scan rate | Port scans / host sweeps |
| `exfiltration_detector` | Random Forest | Upload/download ratio, payload size, flow duration | Data exfiltration |

All models are exported to **ONNX** via `inference/export_onnx.py` for deployment.

---

## 🚀 Quick Start

### Prerequisites

- Python **3.9+**
- Docker & Docker Compose (for the full pipeline)
- `pip install -r requirements.txt` (local dev only)

### Option A — Full Docker Stack (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/<your-org>/SIH_26145.git
cd SIH_26145

# 2. Start all services (Kafka, ClickHouse, ingestor, inference, dashboard)
docker compose up --build

# 3. Open the dashboard
open http://localhost:8000
```

> **First run note:** `model-export` service runs once to compile all sklearn/LightGBM models to ONNX before inference starts. This takes ~60 s.

### Option B — Local Dev (Python only)

#### Step 1 — Generate Synthetic Training Data

```bash
python tools/traffic_gen/syn_flood_gen.py
python tools/traffic_gen/c2_beacon_gen.py
python tools/traffic_gen/dns_tunnel_gen.py
python tools/traffic_gen/port_scan_gen.py
```

#### Step 2 — Train ML Models

```bash
python models/train/dataset_generator.py
python models/train/ddos_train.py
python models/train/beaconing_train.py
python models/train/dga_train.py
python models/train/encrypted_train.py
python models/train/recon_train.py
python models/train/exfil_train.py
```

#### Step 3 — Start the Dashboard

```bash
python -m uvicorn dashboard.api.server:app --port 8000
```

#### Step 4 — View Dashboard & Live Demo

Open [http://localhost:8000](http://localhost:8000) and click **"Start Live Demo Replay"** (top-right) to watch a simulated attack scenario with live alert streaming.

---

## 🐳 Docker Services

| Service | Image | Role |
|---|---|---|
| `zookeeper` | `confluentinc/cp-zookeeper:7.6.1` | Kafka metadata coordination |
| `kafka` | `confluentinc/cp-kafka:7.6.1` | Universal data bus |
| `kafka-init` | cp-kafka | Creates topics on first launch |
| `clickhouse` | `clickhouse/clickhouse-server:24.3` | Columnar alert store |
| `model-export` | python-base | Compiles models to ONNX (runs once) |
| `ingestor` | rust-builder | Rust PCAP replay → `raw-features` topic |
| `inference` | python-base | ONNX scoring × 2 replicas |
| `dashboard` | dashboard | FastAPI REST API + SSE, port `8000` |

Scale inference workers horizontally:
```bash
docker compose up --scale inference=4
```

---

## 📊 Dataset & Replay

See [README-datasets.md](README-datasets.md) for full documentation on:

- Generating labeled PCAP datasets for each attack type
- Feature extraction backends (nfstream / Scapy / Zeek)
- Switching between **Simulated** and **Dataset Replay** modes in the dashboard
- Integrating public datasets (CIC-IDS2017, CTU-13, DGA corpus)

**Supported attack families:**

| Attack | Generator | Severity |
|---|---|---|
| SYN Flood | hping3 / Scapy | CRITICAL |
| UDP Flood | hping3 / Scapy | HIGH |
| Slowloris | Scapy | HIGH |
| DNS Tunnelling | dnscat2 / Scapy | CRITICAL |
| DGA Beaconing (GameOver Zeus, Ramnit, CryptoLocker) | Scapy | CRITICAL |
| Port Scan | Scapy | MEDIUM |
| Benign baseline | iperf3 / Scapy | LOW |

---

## 🔬 Benchmarks

```bash
# Throughput test (packets per second)
python benchmarks/throughput_test.py

# End-to-end alert latency
python benchmarks/latency_test.py

# Adversarial evasion test
python benchmarks/adversarial_test.py

# Full replay harness with labeled ground truth
python benchmarks/replay_harness.py
```

---

## 🗂️ Repository Layout

```
SIH_26145/
├── alerting/           # Alert normalization, correlation, ClickHouse sink, calibration
├── assembler/          # Flow session tables (5-tuple reassembly)
├── benchmarks/         # Throughput, latency, adversarial, replay harnesses
├── dashboard/
│   ├── api/            # FastAPI server (REST + SSE)
│   └── app/            # Web UI (charts, alert table, top-talkers)
├── data/               # PCAP files and generated datasets
├── datasource/         # DataSource ABC: SimulatedSource, DatasetReplaySource
├── docs/               # Additional design documents
├── features/           # Per-threat online feature extractors
├── inference/
│   ├── worker.py       # Kafka consumer + orchestrator
│   ├── onnx_engine.py  # ONNX Runtime inference
│   └── export_onnx.py  # Model → ONNX compiler
├── ingest/
│   ├── rust-ingestor/  # Rust: libpcap → Kafka (50k PPS)
│   ├── pcap_reader.py  # Python fallback reader
│   └── zeek_reader.py  # Zeek log reader
├── models/             # Detector classes + training scripts
├── parsers/            # Protocol parsers (DNS, TLS, HTTP)
├── scripts/            # Traffic generation & feature extraction helpers
├── tests/              # Unit and integration tests
├── tools/              # Traffic generators (syn_flood, c2_beacon, dns_tunnel, port_scan)
├── docker-compose.yml  # Full production stack
├── Dockerfile          # Multi-stage: Rust ingestor + Python inference + dashboard
├── requirements.txt    # Python dependencies
├── start_all.py        # One-shot local dev launcher
└── README-datasets.md  # Dataset layer documentation
```

---

## ⚙️ Configuration

Key environment variables (set in `docker-compose.yml` or `.env`):

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BROKER` | `kafka:9092` | Kafka bootstrap server |
| `CLICKHOUSE_HOST` | `clickhouse` | ClickHouse hostname |
| `CLICKHOUSE_PORT` | `9000` | ClickHouse native port |
| `ONNX_MODELS_DIR` | `/app/models/train/onnx` | Path to compiled ONNX models |
| `INFERENCE_BATCH_SIZE` | `256` | Batch size for ONNX inference |
| `INFERENCE_WORKERS` | `4` | Threads per inference container |
| `PIPELINE_MODE` | `kafka` | `kafka` or `simulated` |

---

## 🛡️ Architecture Constraints

| Constraint | Implementation |
|---|---|
| **Zero outbound TCP ACKs / probes** | Ingest module uses passive libpcap — no injection mode |
| **Bounded memory per flow** | Welford's online algorithm + HyperLogLog for cardinality |
| **Physical gap enforcement** | Dashboard reads ClickHouse only; cannot command the sensor NIC |
| **Transparent fallback** | Every tool dependency (hping3, dnscat2, iperf3) falls back to a Scapy generator when not found; fallback is logged and tagged in `labels.json` |

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 📦 Dependencies

### Core Python

| Package | Purpose |
|---|---|
| `scapy` | Packet crafting & fallback PCAP generation |
| `dpkt` | Lightweight PCAP parsing |
| `fastapi` + `uvicorn` | Dashboard REST API & SSE |
| `scikit-learn` | RF, Isolation Forest, OCSVM models |
| `lightgbm` | Gradient boosting detectors |
| `torch` | Deep learning feature embeddings |
| `pandas` | Feature aggregation & CSV I/O |
| `confluent-kafka ≥ 2.3.0` | Kafka producer/consumer |
| `onnxruntime ≥ 1.18.0` | ONNX model inference |
| `skl2onnx ≥ 1.16.0` | sklearn → ONNX export |
| `clickhouse-driver ≥ 0.2.9` | ClickHouse native protocol |

### Infrastructure

| Service | Version |
|---|---|
| Apache Kafka | Confluent 7.6.1 |
| ClickHouse | 24.3 |
| Rust toolchain | 1.78+ |

---

## ⚠️ Security Notice

> **LAB / ISOLATED NETWORK USE ONLY.**
> All traffic-generation scripts produce synthetic attack packets for IDS/ML evaluation purposes.
> **Do not run against production systems, cloud infrastructure, or any public IP space.**
> The maintainers accept no liability for misuse.

---

## 🤝 Contributing

1. Fork the repository and create a feature branch: `git checkout -b feature/my-feature`
2. Follow existing code style (PEP 8 for Python, `rustfmt` for Rust)
3. Add tests in `tests/` for any new detector or feature extractor
4. Open a pull request with a clear description of the change

---

## 📄 License

This project is released under the [MIT License](LICENSE).

---

*Built for Smart India Hackathon 2025 — Problem Statement 26145*
