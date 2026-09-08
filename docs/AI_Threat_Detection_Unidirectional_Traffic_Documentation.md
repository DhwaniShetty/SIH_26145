# AI Threat Detection for Unidirectional Traffic

## 8. Performance & Scalability (Benchmarking Results)

This section provides concrete measurements of the system's operational envelope, based on the `benchmarks/` suite.

### 8.1 Throughput and Resource Footprint
Running the pipeline fully end-to-end (ingest, parsing, feature extraction, all 6 ML detectors) on a synthetic test file (`data/syn_flood.pcap`):
- **Sustained Packet Rate**: `~59 pps` (Python reference implementation without batching/C extensions)
- **Sustained Throughput**: `~0.03 Mbps`
- **CPU Footprint**: `~900%` (across 8-10 cores due to threading and sklearn/LGBM internals)
- **Memory (RSS)**: `~337 MB`

*Reproduce via:* `python benchmarks/throughput_test.py`

### 8.2 End-to-End Latency
The time elapsed from the ingestion of a malicious packet to the emission of a classified, normalized `AlertRecord` to the SQLite store:
- **Mean Latency**: `1.54 ms`
- **95th Percentile (p95) Latency**: `0.24 ms` (Note: highly dependent on batching and I/O wait times; the pipeline heavily favors fast paths for deterministic hits).

*Reproduce via:* `python benchmarks/latency_test.py`

### 8.3 Adversarial Evasion Robustness
The models have been stress-tested against evasion techniques, yielding the following degradation curves:

**Beaconing Jitter (One-Class SVM)**
- Jitter CV 0.01 - 0.30: Detector Confidence `0.85` - `0.90` (Detected)
- Jitter CV >= 0.50: Detector Confidence `0.00` (Evasion Successful)

**Slow-and-Low Recon (Isolation Forest)**
- Scan Rate >= 100 flows/sec: Confidence `0.90` (Detected)
- Scan Rate <= 50 flows/sec: Confidence `0.00` (Evasion Successful)

*Reproduce via:* `python benchmarks/adversarial_test.py`
