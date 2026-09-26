# Sentrix — Dataset Ingestion Layer

> ⚠️ **LAB NETWORK ONLY**: All traffic generation scripts are designed exclusively for
> isolated lab environments (a private VLAN or a virtual/private network).
> **Never run attack traffic generators against production systems, cloud resources,
> or any public IP space.** The maintainers accept no liability for misuse.

---

## Overview

This layer replaces the randomly-simulated traffic feed with a fully labeled,
ground-truth dataset pipeline.  The dashboard **Config → Data Source** toggle
switches between two modes at runtime:

| Mode | Description |
|------|-------------|
| **Simulated** | Existing PCAP-replay + ONNX inference pipeline (default) |
| **Dataset Replay** | Streams pre-labeled flow records from `data/datasets/` |

Both modes feed the **same** rendering pipeline:
`Live Event Stream → Traffic Monitoring → Threat Summary → Top Talkers`.

---

## Architecture

```
scripts/generate_traffic.py         ← produces PCAP + labels.json
         │
         ▼
scripts/extract_features.py         ← nfstream (preferred) or Scapy fallback
         │                            produces  data/datasets/<attack>/features.csv
         ▼
datasource/dataset_replay.py        ← DatasetReplaySource
         │   streams FlowRecord objects at wall-clock speed
         ▼
dashboard/api/server.py             ← /api/stream (SSE) + /api/replay endpoint
         │   data_source_mode toggle selects Simulated vs. DatasetReplay
         ▼
dashboard/app/ (unchanged UI)       ← existing charts, table, toasts
```

The `datasource/` package exposes a clean `DataSource` ABC so future sources
(live Zeek, Kafka, ClickHouse export) can be plugged in without touching UI code.

---

## Dependencies

### Required (already in `requirements.txt`)
| Package | Purpose |
|---------|---------|
| `scapy` | Fallback PCAP generation + feature extraction |
| `dpkt`  | Lightweight PCAP reading in simulation pipeline |
| `requests` | Already present |

### Optional — install for richer feature extraction
```bash
pip install nfstream          # best feature set, no external binaries
pip install pyshark           # Wireshark-backed alternative (requires tshark)
```

### External Tools & Scapy Fallback (Deliberate Hackathon Tradeoff)
| Tool | Purpose | Platform | Install |
|------|---------|----------|---------|
| `hping3` | SYN/UDP flood generation | Linux / macOS | `apt install hping3` |
| `iperf3` | Benign TCP/UDP baseline | Linux/macOS/Win | <https://iperf.fr> |
| `slowhttptest` / `slowloris` | Slowloris HTTP exhaustion | Linux / macOS | `apt install slowhttptest` |
| `dnscat2` / `iodine` | DNS tunneling | Linux / macOS | <https://github.com/iagox86/dnscat2> |
| `Ostinato` / `TRex` | Protocol-realistic packet loads | Linux / Windows | <https://ostinato.org> |

> **Transparent Fallback Architecture**: Real external tools are invoked via subprocess whenever they are detected on the system PATH. When an external tool is not found, the generator visibly logs:
> `[FALLBACK] <tool> not found -- using synthetic Scapy generator for <attack> traffic`
> and produces structurally equivalent packets via Scapy. Every event in `labels.json` is tagged with `"generator_mode": "real" | "fallback"`. This is a deliberate hackathon-scope design decision ensuring the ingestion pipeline is 100% demo-ready and testable across all developer environments without requiring root privileges or complex binary compilation.

---

## Quick Start

### Step 1 — Generate labeled traffic (lab network only)

```bash
# Generate all attack types (Scapy fallback, no external tools needed)
python scripts/generate_traffic.py --attack all --target 192.168.100.1 --duration 20

# Or individual types:
python scripts/generate_traffic.py --attack syn_flood  --target 192.168.100.1 --rate 5000
python scripts/generate_traffic.py --attack dns_tunnel --target 192.168.100.1 --duration 30
python scripts/generate_traffic.py --attack dga_beacon --target 192.168.100.1 --dga-family gameover_zeus
python scripts/generate_traffic.py --attack slowloris  --target 192.168.100.1 --connections 300
python scripts/generate_traffic.py --attack port_scan  --target 192.168.100.1
python scripts/generate_traffic.py --attack benign     --target 192.168.100.1
```

This writes to `data/datasets/<attack>/`:
- `packets.pcap`  — raw capture
- `labels.json`   — ground-truth sidecar (timestamp, 5-tuple, attack_family, severity, generator)

### Step 2 — Extract features

```bash
# Batch-process all generated PCAPs
python scripts/extract_features.py --input-dir data/datasets/

# Or single file with explicit backend
python scripts/extract_features.py \
  --pcap   data/datasets/syn_flood/packets.pcap \
  --labels data/datasets/syn_flood/labels.json \
  --output data/datasets/syn_flood/features.csv \
  --backend nfstream
```

This writes `data/datasets/<attack>/features.csv` with columns:

| Column group | Columns |
|---|---|
| 5-tuple + timing | `src_ip, dst_ip, src_port, dst_port, protocol, timestamp, duration_s` |
| Volumetric | `pkt_count, byte_count, pkts_per_sec, bytes_per_sec, avg_pkt_size` |
| IAT timing | `iat_mean_ms, iat_std_ms, iat_min_ms, iat_max_ms` |
| TCP flags | `syn_count, ack_count, fin_count, rst_count, syn_synack_ratio` |
| DNS | `dns_query_len, dns_entropy` |
| Ground truth | `attack_family, severity, generator` |

### Step 3 — Enable Dataset Replay in the dashboard

1. Open the dashboard (`http://localhost:8000`)
2. Click **⚙️ CONFIG**
3. Under **Data Source**, switch to **Dataset Replay**
4. Click **▶ START** — the existing charts will begin streaming labeled data

The replay cycles continuously through all available `features.csv` files,
pacing records at real-time speed (configurable via `speed_factor` in server.py).

---

## Traffic Generation Details

### Benign traffic
- **iperf3** (if available): measures baseline TCP/UDP load
- **Scapy**: generates HTTP GET, HTTPS, SSH session simulations
- Labels: `attack_family=BENIGN, severity=LOW`

### SYN Flood
- **hping3** (preferred): `hping3 -S -p 80 --flood --rand-source <target>`
- **Scapy fallback**: crafts raw SYN packets with randomised spoofed source IPs
- Labels: `attack_family=SYN_FLOOD, severity=CRITICAL`

### UDP Flood
- **hping3**: `hping3 --udp --flood -p <port> <target>`
- **Scapy fallback**: large UDP datagrams from random sources
- Labels: `attack_family=UDP_FLOOD, severity=HIGH`

### Slowloris (Slow HTTP Exhaustion)
- **Scapy**: sends partial HTTP headers to exhaust thread pool
- Use `--connections` to set concurrent hold-open connections
- Labels: `attack_family=SLOWLORIS, severity=HIGH`

### DNS Tunneling
- **dnscat2 / iodine** (if available): real DNS over UDP tunnel
- **Scapy fallback**: high-entropy base32-encoded subdomain queries
- Labels: `attack_family=DNS_TUNNEL, severity=CRITICAL`

### DGA Beaconing
- Always Scapy-based; three built-in DGA algorithm implementations:
  - `gameover_zeus` — arithmetic DGA
  - `ramnit`       — date-based DGA (MD5)
  - `cryptolocker` — random seed DGA
- Configurable beacon interval + Gaussian jitter
- Labels: `attack_family=C2_BEACON, severity=CRITICAL`

---

## Feature Extraction Backends

| Backend | Pros | Cons |
|---|---|---|
| **nfstream** (recommended) | Rich features, bidirectional stats, DNS dissection, no external tools | `pip install nfstream` required |
| **Scapy** (default fallback) | Always available, no extra install | Slower on large PCAPs; fewer DNS features |
| **Zeek** (future) | Industry-standard, full protocol analysis | Requires Zeek installation (Linux/macOS only) |

---

## Public Dataset Integration

The following datasets can be downloaded and placed in `data/datasets/` for replay.
Use `scripts/extract_features.py` to normalise any CSV that contains a 5-tuple.

| Dataset | URL | Format | License |
|---|---|---|---|
| CIC-IDS2017 | <https://www.unb.ca/cic/datasets/ids-2017.html> | PCAP + CSV | Research only |
| CSE-CIC-IDS2018 | <https://registry.opendata.aws/cse-cic-ids2018/> | CSV | Research only |
| CTU-13 (botnets) | <https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/> | PCAP | Open |
| DGA corpus | <https://data.netlab.360.com/feeds/dga/dga.txt> | TXT | Open |

---

## DataSource Interface

```python
from datasource import SimulatedSource, DatasetReplaySource

# Simulated (existing ONNX pipeline)
src = SimulatedSource(db_path=..., telemetry_path=..., script_path=...)
src.start(scenario="massive_ddos", duration=60)

# Dataset Replay
src = DatasetReplaySource(data_dir="data/", speed_factor=2.0)
src.start(scenario="stealth_c2_exfil", duration=120)

alerts = src.read_alerts(since_ts=time.time() - 5)
telem  = src.read_telemetry()
src.stop()
```

Both implement `DataSource` (see `datasource/base.py`) and emit identical
`AlertRecord`-compatible dicts, making them **fully interchangeable** in the
dashboard API layer.

---

## Security & Compliance Notes

- All generated PCAPs contain **synthetic payloads** — no real user data
- The Slowloris and DNS-tunnel generators produce **structurally realistic but benign** bytes
- hping3 and dnscat2 are **external tools** — ensure they are installed and licensed appropriately for your jurisdiction
- Label files (labels.json) are the **sole authoritative ground truth** — do not use PCAP payload for classification
- Generated datasets are intended for **IDS/ML model evaluation only**
