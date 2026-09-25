"""
datasource/dataset_replay.py
================================
Streams pre-labeled flow records from the synthetic/generated datasets
(data/datasets/*.csv  or  data/*_labels.json) through the dashboard rendering
pipeline at either real-time or scaled capture speed.

Architecture
------------
  DatasetReplaySource.start()
      |-- _replay_thread()
            |-- loads CSV/JSON label files, iterates records with wall-clock
               pacing, converts each to FlowRecord, enqueues to _alert_queue
  read_alerts()   - drains _alert_queue
  read_telemetry() - returns rolling stats computed during replay
"""
from __future__ import annotations

import csv
import glob
import json
import math
import os
import queue
import random
import threading
import time
from typing import Any, Dict, List, Optional

from .base import DataSource, FlowRecord

# ── Severity classification by attack family ──────────────────────────────────
_SEVERITY_MAP: Dict[str, str] = {
    "BENIGN": "LOW",
    "SYN_FLOOD": "CRITICAL",
    "UDP_FLOOD": "HIGH",
    "UDP_AMPLIFICATION": "CRITICAL",
    "SLOWLORIS": "HIGH",
    "DNS_TUNNEL": "CRITICAL",
    "DNS_EXFIL": "HIGH",
    "DGA": "HIGH",
    "C2_BEACON": "CRITICAL",
    "PORT_SCAN": "MEDIUM",
    "RECON": "MEDIUM",
    "EXFIL": "HIGH",
}

_CONFIDENCE_MAP: Dict[str, float] = {
    "BENIGN": 0.1,
    "SYN_FLOOD": 0.97,
    "UDP_FLOOD": 0.93,
    "UDP_AMPLIFICATION": 0.98,
    "SLOWLORIS": 0.88,
    "DNS_TUNNEL": 0.95,
    "DNS_EXFIL": 0.91,
    "DGA": 0.87,
    "C2_BEACON": 0.94,
    "PORT_SCAN": 0.82,
    "RECON": 0.79,
    "EXFIL": 0.86,
}

# ── Scenario → attack-family weights ─────────────────────────────────────────
SCENARIO_WEIGHTS: Dict[str, Dict[str, float]] = {
    "random": {},           # equal weight across all available families
    "massive_ddos": {"SYN_FLOOD": 0.45, "UDP_AMPLIFICATION": 0.30, "BENIGN": 0.25},
    "stealth_c2_exfil": {"C2_BEACON": 0.35, "DNS_TUNNEL": 0.30, "EXFIL": 0.15, "BENIGN": 0.20},
    "recon_storm": {"PORT_SCAN": 0.55, "RECON": 0.30, "BENIGN": 0.15},
    "quiet_hours": {"BENIGN": 0.90, "PORT_SCAN": 0.05, "C2_BEACON": 0.05},
    "coordinated_campaign": {"SYN_FLOOD": 0.25, "C2_BEACON": 0.20, "DNS_TUNNEL": 0.15,
                              "PORT_SCAN": 0.20, "BENIGN": 0.20},
}


class DatasetReplaySource(DataSource):
    """
    Streams labeled dataset records into the dashboard at wall-clock speed.

    Data discovery order (first match wins):
      1. data/datasets/*.csv   – output of scripts/extract_features.py
      2. data/*_labels.json    – existing project label sidecars
    """

    def __init__(self, data_dir: str, speed_factor: float = 1.0, max_queue: int = 5000):
        """
        Args:
            data_dir:     Absolute path to the project data/ directory.
            speed_factor: Replay speed multiplier.  1.0 = real time, 10.0 = 10× faster.
            max_queue:    Maximum buffered alerts in memory.
        """
        self._data_dir = data_dir
        self._speed = max(0.01, speed_factor)
        self._alert_queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Live telemetry counters
        self._telem_lock = threading.Lock()
        self._pkts = 0
        self._bytes = 0
        self._flows: set = set()
        self._telem_t0 = time.time()
        self._scenario = "random"

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self, scenario: str = "random", duration: Optional[float] = None) -> None:
        self.stop()
        self._stop_event.clear()
        self._scenario = scenario
        self._thread = threading.Thread(
            target=self._replay_thread, args=(duration,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None
        # flush queue
        while not self._alert_queue.empty():
            try:
                self._alert_queue.get_nowait()
            except queue.Empty:
                break

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def read_alerts(self, since_ts: float) -> List[dict]:
        """Drain buffered FlowRecord.to_alert_dict() entries newer than since_ts."""
        results = []
        while True:
            try:
                rec: FlowRecord = self._alert_queue.get_nowait()
                if rec.timestamp > since_ts and rec.attack_family.upper() != "BENIGN":
                    results.append(rec.to_alert_dict())
            except queue.Empty:
                break
        return results

    def read_telemetry(self) -> dict:
        with self._telem_lock:
            elapsed = max(0.001, time.time() - self._telem_t0)
            pps = self._pkts / elapsed
            mbps = (self._bytes * 8) / (elapsed * 1_000_000)
            flows = len(self._flows)
        j = random.uniform(0.97, 1.03)
        return {
            "pkts_per_sec": int(pps * j) or int(1200 * j),
            "mbps": round(mbps * j, 1) or round(8.4 * j, 1),
            "active_flows": flows or int(48 * j),
            "latency_ms": round(random.uniform(0.6, 1.8), 2),
            "diode_mode": "DATASET REPLAY (Labeled Ground Truth)",
            "status": "STREAMING" if self.is_running() else "IDLE_BASELINE",
            "updated_at": time.time(),
        }

    # ── Data loading ──────────────────────────────────────────────────────────

    def _load_records(self) -> List[FlowRecord]:
        """Load all available labeled records from CSV and JSON sidecar files."""
        records: List[FlowRecord] = []

        # 1. CSV files from scripts/extract_features.py output
        csv_pattern = os.path.join(self._data_dir, "datasets", "*.csv")
        for csv_path in sorted(glob.glob(csv_pattern)):
            records.extend(self._load_csv(csv_path))

        # 2. Existing JSON label sidecars from data/ and data/datasets/
        json_patterns = [
            os.path.join(self._data_dir, "*_labels.json"),
            os.path.join(self._data_dir, "datasets", "*", "labels.json"),
            os.path.join(self._data_dir, "datasets", "*_labels.json"),
        ]
        for pattern in json_patterns:
            for json_path in sorted(glob.glob(pattern)):
                records.extend(self._load_json_labels(json_path))

        return records

    def _load_csv(self, path: str) -> List[FlowRecord]:
        """Parse feature CSV produced by extract_features.py."""
        records = []
        try:
            with open(path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    family = row.get("attack_family", "BENIGN").upper().replace(" ", "_")
                    rec = FlowRecord(
                        timestamp=float(row.get("timestamp", time.time())),
                        src_ip=row.get("src_ip", "0.0.0.0"),
                        dst_ip=row.get("dst_ip", "0.0.0.0"),
                        src_port=int(float(row.get("src_port", 0))),
                        dst_port=int(float(row.get("dst_port", 0))),
                        protocol=row.get("protocol", "TCP"),
                        attack_family=family,
                        severity=_SEVERITY_MAP.get(family, "LOW"),
                        confidence=_CONFIDENCE_MAP.get(family, 0.75),
                        generator=row.get("generator", "nfstream"),
                        pkt_count=int(float(row.get("pkt_count", 0))),
                        byte_count=int(float(row.get("byte_count", 0))),
                        duration_s=float(row.get("duration_s", 0.0)),
                        features={
                            k: _try_float(v)
                            for k, v in row.items()
                            if k not in {"timestamp", "src_ip", "dst_ip", "src_port",
                                         "dst_port", "protocol", "attack_family",
                                         "severity", "generator"}
                        },
                        explanation=f"Dataset replay [{os.path.basename(path)}]: {family}",
                    )
                    records.append(rec)
        except Exception as e:
            print(f"[DatasetReplay] Warning: could not load {path}: {e}")
        return records

    def _load_json_labels(self, path: str) -> List[FlowRecord]:
        """Parse existing *_labels.json sidecars."""
        records = []
        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
            # Support both list-of-dicts and {"labels": [...]}
            if isinstance(raw, dict):
                raw = raw.get("labels", raw.get("packets", []))
            for entry in raw:
                family = str(entry.get("attack_family",
                             entry.get("label", "BENIGN"))).upper().replace(" ", "_")
                if family == "BENIGN":
                    continue  # skip benign to reduce noise in the event stream
                ts = float(entry.get("timestamp", time.time()))
                flow = entry.get("flow", {})
                rec = FlowRecord(
                    timestamp=ts,
                    src_ip=flow.get("src_ip", entry.get("src_ip", "0.0.0.0")),
                    dst_ip=flow.get("dst_ip", entry.get("dst_ip", "0.0.0.0")),
                    src_port=int(flow.get("src_port", entry.get("src_port", 0))),
                    dst_port=int(flow.get("dst_port", entry.get("dst_port", 0))),
                    protocol=flow.get("protocol", entry.get("protocol", "TCP")),
                    attack_family=family,
                    severity=_SEVERITY_MAP.get(family, "MEDIUM"),
                    confidence=float(entry.get("confidence",
                                    _CONFIDENCE_MAP.get(family, 0.80))),
                    generator=entry.get("generator", "dataset"),
                    pkt_count=int(entry.get("pkt_count", 1)),
                    byte_count=int(entry.get("byte_count", len(str(entry)))),
                    duration_s=float(entry.get("duration_s", 0.001)),
                    features=entry.get("features", {}),
                    explanation=entry.get("explanation",
                                f"Dataset replay [{os.path.basename(path)}]: {family}"),
                )
                records.append(rec)
        except Exception as e:
            print(f"[DatasetReplay] Warning: could not load {path}: {e}")
        return records

    # ── Replay thread ─────────────────────────────────────────────────────────

    def _replay_thread(self, duration: Optional[float]) -> None:
        """Background thread that paces and enqueues FlowRecords."""
        records = self._load_records()

        if not records:
            # Fallback: synthesize minimal realistic records
            records = _synthesize_fallback_records(self._scenario, count=500)
            print("[DatasetReplay] No dataset files found — using synthetic fallback records.")
        else:
            # Filter by scenario weights
            records = _filter_by_scenario(records, self._scenario)
            print(f"[DatasetReplay] Loaded {len(records)} labeled records for scenario '{self._scenario}'.")

        # Sort by original timestamp so inter-arrival times are meaningful
        records.sort(key=lambda r: r.timestamp)

        t0 = time.perf_counter()
        ref_ts = records[0].timestamp if records else time.time()
        wall_t0 = time.time()

        with self._telem_lock:
            self._pkts = 0
            self._bytes = 0
            self._flows = set()
            self._telem_t0 = time.time()

        loop = True
        while loop and not self._stop_event.is_set():
            for i, rec in enumerate(records):
                if self._stop_event.is_set():
                    return
                if duration and (time.perf_counter() - t0) >= duration:
                    return

                # Remap timestamp to wall clock
                offset = (rec.timestamp - ref_ts) / self._speed
                rec.timestamp = wall_t0 + offset

                # Telemetry accounting
                with self._telem_lock:
                    self._pkts += rec.pkt_count or 1
                    self._bytes += rec.byte_count or 256
                    self._flows.add((rec.src_ip, rec.dst_ip, rec.dst_port))

                # Enqueue (drop if full to avoid memory blow-up)
                try:
                    self._alert_queue.put_nowait(rec)
                except queue.Full:
                    pass

                # Pace replay to match inter-arrival times at configured speed
                if i + 1 < len(records):
                    next_offset = (records[i + 1].timestamp - ref_ts) / self._speed
                    sleep_s = (wall_t0 + next_offset) - time.time()
                    if sleep_s > 0.005:
                        self._stop_event.wait(timeout=min(sleep_s, 0.5))

            # Continuous loop — re-run the dataset from the start
            ref_ts = records[0].timestamp
            wall_t0 = time.time()
            with self._telem_lock:
                self._telem_t0 = time.time()

    # ── Statistics helpers ────────────────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        """Threat class counts across all queued records (for threat-summary donut)."""
        counts: Dict[str, int] = {}
        # snapshot
        items = list(self._alert_queue.queue)
        for rec in items:
            if isinstance(rec, FlowRecord):
                k = rec.attack_family
                counts[k] = counts.get(k, 0) + 1
        return counts


# ── Helpers ───────────────────────────────────────────────────────────────────

def _try_float(val: str) -> Any:
    try:
        return float(val)
    except (ValueError, TypeError):
        return val


def _filter_by_scenario(records: List[FlowRecord], scenario: str) -> List[FlowRecord]:
    """Subsample records to match scenario threat-mix weights."""
    weights = SCENARIO_WEIGHTS.get(scenario, {})
    if not weights:
        return records

    by_family: Dict[str, List[FlowRecord]] = {}
    for r in records:
        by_family.setdefault(r.attack_family.upper(), []).append(r)

    all_families = list(by_family.keys())
    total = len(records)
    result = []
    for family, w in weights.items():
        target = int(total * w)
        pool = by_family.get(family, [])
        if pool:
            # repeat-sample to hit target count
            sampled = []
            while len(sampled) < target:
                sampled.extend(pool)
            result.extend(sampled[:target])

    # Include unlisted families with equal residual weight
    listed = set(weights.keys())
    unlisted = [f for f in all_families if f not in listed]
    if unlisted:
        residual = max(0, total - len(result))
        per = residual // len(unlisted) if unlisted else 0
        for f in unlisted:
            pool = by_family.get(f, [])
            sampled = []
            while len(sampled) < per:
                sampled.extend(pool)
            result.extend(sampled[:per])

    random.shuffle(result)
    return result or records  # fallback to full set if filtering produced nothing


def _synthesize_fallback_records(scenario: str, count: int = 500) -> List[FlowRecord]:
    """Generate minimal synthetic FlowRecords when no dataset files are found."""
    weights = SCENARIO_WEIGHTS.get(scenario, {
        "SYN_FLOOD": 0.15, "UDP_AMPLIFICATION": 0.10, "C2_BEACON": 0.15,
        "DNS_TUNNEL": 0.15, "PORT_SCAN": 0.20, "BENIGN": 0.25,
    })
    records = []
    t = time.time()
    for family, w in weights.items():
        n = max(1, int(count * w))
        for i in range(n):
            src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            dst = f"192.168.{random.randint(0,10)}.{random.randint(1,254)}"
            proto = "UDP" if "DNS" in family or "UDP" in family else "TCP"
            dport = 53 if "DNS" in family else (80 if "HTTP" in family or family == "BENIGN"
                    else (443 if "C2" in family or "BEACON" in family else random.randint(1024,65535)))
            feats = _fake_features(family)
            records.append(FlowRecord(
                timestamp=t + i * 0.05 + random.uniform(0, 0.02),
                src_ip=src,
                dst_ip=dst,
                src_port=random.randint(1024, 65535),
                dst_port=dport,
                protocol=proto,
                attack_family=family,
                severity=_SEVERITY_MAP.get(family, "LOW"),
                confidence=_CONFIDENCE_MAP.get(family, 0.75) + random.uniform(-0.05, 0.05),
                generator="synthetic_fallback",
                pkt_count=random.randint(1, 500),
                byte_count=random.randint(64, 65000),
                duration_s=round(random.uniform(0.001, 30.0), 3),
                features=feats,
                explanation=f"Synthetic fallback [{scenario}]: {family}",
            ))
    random.shuffle(records)
    return records


def _fake_features(family: str) -> Dict[str, float]:
    if "SYN" in family:
        return {"syn_synack_ratio": random.uniform(10, 50), "dst_pkt_ewma": random.uniform(800, 3000), "src_ip_entropy": random.uniform(3.5, 5.0)}
    if "UDP" in family:
        return {"amp_byte_ratio": random.uniform(10, 80), "dst_pkt_ewma": random.uniform(500, 2000)}
    if "C2" in family or "BEACON" in family:
        return {"iat_cv": random.uniform(0.02, 0.1), "mean_iat": random.uniform(25, 60)}
    if "DNS" in family or "TUNNEL" in family:
        return {"txt_cname_avg_entropy": random.uniform(4.5, 5.5), "txt_cname_avg_len": random.uniform(40, 80), "txt_cname_rate": random.uniform(5, 30)}
    if "PORT" in family or "RECON" in family:
        return {"syn_only_ratio": random.uniform(0.85, 1.0), "scan_activity_score": random.uniform(50, 300)}
    if "EXFIL" in family:
        return {"outbound_inbound_ratio": random.uniform(10, 50), "outbound_bytes_ewma": random.uniform(5000, 50000)}
    return {"pkt_rate": random.uniform(10, 200)}
