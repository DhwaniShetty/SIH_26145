"""
datasource/feature_extractor.py
=================================
Extracts flow-level features from PCAP files.

Priority order (auto-detected):
  1. nfstream  (pure Python, pip install nfstream)
  2. scapy     (already a project dependency)

Outputs a CSV/Parquet file with the required 5-tuple + feature columns,
consumable by DatasetReplaySource.
"""
from __future__ import annotations

import csv
import importlib
import json
import math
import os
import struct
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ─── Public API ───────────────────────────────────────────────────────────────

def extract_features(pcap_path: str,
                     label_path: Optional[str] = None,
                     output_path: Optional[str] = None,
                     backend: str = "auto") -> List[dict]:
    """
    Extract per-flow features from a PCAP file.

    Args:
        pcap_path:   Path to input PCAP.
        label_path:  Optional JSON sidecar with ground-truth labels (same format
                     as data/*_labels.json).  If None, all flows are tagged BENIGN.
        output_path: If provided, results are also written as CSV to this path.
        backend:     "auto" | "nfstream" | "scapy"

    Returns:
        List of dicts, each representing one bi-directional flow.
    """
    chosen = _pick_backend(backend)
    if chosen == "nfstream":
        rows = _extract_nfstream(pcap_path)
    else:
        rows = _extract_scapy(pcap_path)

    # Attach ground-truth labels
    if label_path and os.path.exists(label_path):
        rows = _apply_labels(rows, label_path)

    if output_path:
        _write_csv(rows, output_path)

    return rows


# ─── Backend selection ────────────────────────────────────────────────────────

def _pick_backend(preference: str) -> str:
    if preference == "nfstream":
        return "nfstream" if _have("nfstream") else "scapy"
    if preference == "scapy":
        return "scapy"
    # auto: prefer nfstream
    return "nfstream" if _have("nfstream") else "scapy"


def _have(pkg: str) -> bool:
    try:
        importlib.import_module(pkg)
        return True
    except ImportError:
        return False


# ─── nfstream backend ─────────────────────────────────────────────────────────

def _extract_nfstream(pcap_path: str) -> List[dict]:
    """Use nfstream for rich flow-level feature extraction."""
    try:
        from nfstream import NFStreamer
    except ImportError:
        raise RuntimeError("nfstream is not installed.  Run: pip install nfstream")

    rows = []
    streamer = NFStreamer(source=pcap_path,
                          statistical_analysis=True,
                          splt_analysis=0,
                          n_dissections=20)
    for flow in streamer:
        # Inter-arrival times
        mean_iat = getattr(flow, "bidirectional_mean_ps_iat_ms", 0) or 0
        std_iat  = getattr(flow, "bidirectional_stddev_ps_iat_ms", 0) or 0
        min_iat  = getattr(flow, "bidirectional_min_ps_iat_ms", 0) or 0
        max_iat  = getattr(flow, "bidirectional_max_ps_iat_ms", 0) or 0

        pkt_count  = getattr(flow, "bidirectional_packets", 0) or 0
        byte_count = getattr(flow, "bidirectional_bytes", 0) or 0
        dur_ms     = getattr(flow, "bidirectional_duration_ms", 1) or 1
        dur_s      = dur_ms / 1000

        pps  = pkt_count / max(dur_s, 0.001)
        bps  = byte_count / max(dur_s, 0.001)
        avg_sz = byte_count / max(pkt_count, 1)

        syn  = getattr(flow, "src2dst_syn_packets", 0) or 0
        ack  = getattr(flow, "src2dst_ack_packets", 0) or 0
        fin  = getattr(flow, "src2dst_fin_packets", 0) or 0
        rst  = getattr(flow, "src2dst_rst_packets", 0) or 0

        row = {
            # 5-tuple
            "src_ip":   flow.src_ip,
            "dst_ip":   flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": "UDP" if flow.protocol == 17 else ("TCP" if flow.protocol == 6 else str(flow.protocol)),
            "timestamp": flow.expiration_id or time.time(),
            "duration_s": round(dur_s, 4),
            # Volumetric
            "pkt_count":  pkt_count,
            "byte_count": byte_count,
            "pkts_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "avg_pkt_size": round(avg_sz, 2),
            # Timing
            "iat_mean_ms": round(mean_iat, 3),
            "iat_std_ms":  round(std_iat, 3),
            "iat_min_ms":  round(min_iat, 3),
            "iat_max_ms":  round(max_iat, 3),
            # TCP flags
            "syn_count": syn,
            "ack_count": ack,
            "fin_count": fin,
            "rst_count": rst,
            "syn_synack_ratio": round(syn / max(ack, 1), 3),
            # DNS (nfstream dissection)
            "dns_query_len": 0,
            "dns_entropy":   0.0,
            # Defaults
            "attack_family": "BENIGN",
            "severity":      "LOW",
            "generator":     "nfstream",
        }
        rows.append(row)
    return rows


# ─── Scapy backend ────────────────────────────────────────────────────────────

def _extract_scapy(pcap_path: str) -> List[dict]:
    """
    Lightweight Scapy-based flow aggregator.
    Produces the same schema as the nfstream backend.
    """
    try:
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS
    except ImportError:
        raise RuntimeError("scapy is not installed.  Run: pip install scapy")

    # flow key → accumulators
    flows: Dict[Tuple, dict] = {}

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
                continue
            ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
            src_ip, dst_ip = str(ip.src), str(ip.dst)
            proto = "TCP"
            sport, dport = 0, 0

            if pkt.haslayer(TCP):
                l4 = pkt[TCP]; sport, dport = l4.sport, l4.dport
            elif pkt.haslayer(UDP):
                l4 = pkt[UDP]; sport, dport = l4.sport, l4.dport; proto = "UDP"
            else:
                proto = "ICMP"

            key = (src_ip, dst_ip, sport, dport, proto)
            ts = float(pkt.time)
            sz = len(pkt)

            if key not in flows:
                flows[key] = {
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "src_port": sport, "dst_port": dport,
                    "protocol": proto,
                    "t_start": ts, "t_end": ts,
                    "pkts": 0, "bytes": 0,
                    "iats": [], "prev_ts": ts,
                    "syn": 0, "ack": 0, "fin": 0, "rst": 0,
                    "dns_lens": [], "dns_bytes": [],
                }
            f = flows[key]
            if f["pkts"] > 0:
                f["iats"].append(ts - f["prev_ts"])
            f["prev_ts"] = ts
            f["t_end"] = max(f["t_end"], ts)
            f["pkts"] += 1
            f["bytes"] += sz

            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x02: f["syn"] += 1
                if flags & 0x10: f["ack"] += 1
                if flags & 0x01: f["fin"] += 1
                if flags & 0x04: f["rst"] += 1

            if pkt.haslayer(DNS) and pkt[DNS].qd:
                qname = bytes(pkt[DNS].qd.qname)
                f["dns_lens"].append(len(qname))
                f["dns_bytes"].append(sz)

    rows = []
    for key, f in flows.items():
        dur_s = max(f["t_end"] - f["t_start"], 0.001)
        iats_ms = [x * 1000 for x in f["iats"]]
        pps = f["pkts"] / dur_s
        bps = f["bytes"] / dur_s
        avg_sz = f["bytes"] / max(f["pkts"], 1)

        mean_iat = sum(iats_ms) / len(iats_ms) if iats_ms else 0.0
        std_iat  = math.sqrt(sum((x - mean_iat)**2 for x in iats_ms) / len(iats_ms)) if len(iats_ms) > 1 else 0.0

        # DNS entropy
        dns_ent = 0.0
        if f["dns_lens"]:
            total_dns = sum(f["dns_bytes"])
            dns_ent = _entropy(f["dns_lens"])

        rows.append({
            "src_ip":   f["src_ip"],
            "dst_ip":   f["dst_ip"],
            "src_port": f["src_port"],
            "dst_port": f["dst_port"],
            "protocol": f["protocol"],
            "timestamp": f["t_start"],
            "duration_s": round(dur_s, 4),
            "pkt_count":  f["pkts"],
            "byte_count": f["bytes"],
            "pkts_per_sec":  round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "avg_pkt_size":  round(avg_sz, 2),
            "iat_mean_ms": round(mean_iat, 3),
            "iat_std_ms":  round(std_iat, 3),
            "iat_min_ms":  round(min(iats_ms, default=0.0), 3),
            "iat_max_ms":  round(max(iats_ms, default=0.0), 3),
            "syn_count": f["syn"],
            "ack_count": f["ack"],
            "fin_count": f["fin"],
            "rst_count": f["rst"],
            "syn_synack_ratio": round(f["syn"] / max(f["ack"], 1), 3),
            "dns_query_len": round(sum(f["dns_lens"]) / len(f["dns_lens"]), 1) if f["dns_lens"] else 0,
            "dns_entropy":   round(dns_ent, 3),
            "attack_family": "BENIGN",
            "severity":      "LOW",
            "generator":     "scapy",
        })
    return rows


# --- Label attachment ---------------------------------------------------------

_SEVERITY_MAP: Dict[str, str] = {
    "BENIGN": "LOW",
    "SYN_FLOOD": "CRITICAL",
    "UDP_FLOOD": "HIGH",
    "UDP_AMPLIFICATION": "CRITICAL",
    "SLOWLORIS": "HIGH",
    "DNS_TUNNEL": "CRITICAL",
    "DNS_EXFIL": "HIGH",
    "DGA": "HIGH",
    "DGA_BEACON": "CRITICAL",
    "C2_BEACON": "CRITICAL",
    "PORT_SCAN": "MEDIUM",
    "RECON": "MEDIUM",
    "EXFIL": "HIGH",
}

def _apply_labels(rows: List[dict], label_path: str) -> List[dict]:
    """Attach ground-truth labels from JSON sidecar to extracted flow rows."""
    try:
        with open(label_path, encoding="utf-8") as f:
            data = json.load(f)
        attack_type = ""
        generator_mode = "dataset"
        raw = []
        if isinstance(data, dict):
            attack_type = str(data.get("attack", "")).upper().replace(" ", "_")
            generator_mode = str(data.get("generator_mode", "dataset"))
            raw = data.get("labels", data.get("packets", []))
        elif isinstance(data, list):
            raw = data

        # Build lookup by (src_ip, dst_ip, dst_port, protocol)
        label_map: Dict[Tuple, dict] = {}
        for entry in raw:
            flow = entry.get("flow", entry)
            key = (
                str(flow.get("src_ip", "")),
                str(flow.get("dst_ip", "")),
                int(flow.get("dst_port", 0)),
                str(flow.get("protocol", "TCP")),
            )
            label_map[key] = entry

        for row in rows:
            key = (row["src_ip"], row["dst_ip"], row["dst_port"], row["protocol"])
            if key in label_map:
                entry = label_map[key]
                family = str(entry.get("attack_family",
                                       entry.get("label", "BENIGN"))).upper().replace(" ", "_")
                row["attack_family"] = family
                row["severity"] = entry.get("severity", _SEVERITY_MAP.get(family, "LOW"))
                row["generator"] = entry.get("generator", row.get("generator", generator_mode))
            elif attack_type and attack_type != "BENIGN":
                # Fallback: flows with randomized ephemeral ports inherit capture's labeled attack
                norm_family = "C2_BEACON" if "DGA" in attack_type else attack_type
                row["attack_family"] = norm_family
                row["severity"] = _SEVERITY_MAP.get(norm_family, "HIGH")
                row["generator"] = generator_mode
    except Exception as e:
        print(f"[FeatureExtractor] Label attachment failed: {e}")
    return rows


# ─── CSV output ───────────────────────────────────────────────────────────────

def _write_csv(rows: List[dict], output_path: str) -> None:
    if not rows:
        return
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    fieldnames = list(rows[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[FeatureExtractor] Wrote {len(rows)} flow records -> {output_path}")


# ─── Maths helpers ────────────────────────────────────────────────────────────

def _entropy(values: List[float]) -> float:
    if not values:
        return 0.0
    total = sum(values)
    if total == 0:
        return 0.0
    probs = [v / total for v in values if v > 0]
    return -sum(p * math.log2(p) for p in probs if p > 0)
