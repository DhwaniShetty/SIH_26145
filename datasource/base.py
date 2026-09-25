"""
datasource/base.py  –  Abstract DataSource interface.

Every concrete source must inherit DataSource and implement:
  start(scenario, duration) -> None
  stop()                   -> None
  read_alerts(since_ts)    -> List[dict]   (AlertRecord-compatible dicts)
  read_telemetry()         -> dict         (pkts_per_sec, mbps, active_flows, …)
  is_running()             -> bool
"""
from __future__ import annotations
import abc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FlowRecord:
    """
    Normalised ground-truth record from a labeled dataset or synthetic generator.
    Maps 1-to-1 onto AlertRecord for dashboard rendering.
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str                      # TCP | UDP | ICMP | DNS | …
    attack_family: str                 # BENIGN | SYN_FLOOD | DNS_TUNNEL | …
    severity: str                      # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float                  # 0.0 – 1.0
    generator: str                     # hping3 | scapy | nfstream | dataset
    features: Dict[str, Any] = field(default_factory=dict)
    explanation: str = ""

    # Volumetric telemetry (per-flow or rolling window)
    pkt_count: int = 0
    byte_count: int = 0
    duration_s: float = 0.0

    def to_alert_dict(self) -> dict:
        """Convert to AlertRecord-compatible dict for the existing dashboard pipeline."""
        import uuid, time
        detector_map = {
            "SYN_FLOOD": "ddos",
            "UDP_FLOOD": "ddos",
            "UDP_AMPLIFICATION": "ddos",
            "SLOWLORIS": "ddos",
            "DNS_TUNNEL": "dns_exfil",
            "DNS_EXFIL": "dns_exfil",
            "DGA": "dga",
            "C2_BEACON": "beaconing",
            "PORT_SCAN": "recon",
            "RECON": "recon",
            "EXFIL": "exfil",
            "BENIGN": "benign",
        }
        family_upper = self.attack_family.upper()
        detector = detector_map.get(family_upper, "unknown")
        threat_class_map = {
            "SYN_FLOOD": "SYN Flood",
            "UDP_FLOOD": "UDP Flood",
            "UDP_AMPLIFICATION": "UDP Amplification",
            "SLOWLORIS": "Slow HTTP Exhaustion",
            "DNS_TUNNEL": "DNS Tunneling",
            "DNS_EXFIL": "DNS Exfiltration",
            "DGA": "DGA Beaconing",
            "C2_BEACON": "C2 Beaconing",
            "PORT_SCAN": "Port Scan",
            "RECON": "Reconnaissance",
            "EXFIL": "Data Exfiltration",
            "BENIGN": "Benign",
        }
        return {
            "alert_id": str(uuid.uuid4()),
            "timestamp": self.timestamp,
            "detector": detector,
            "threat_class": threat_class_map.get(family_upper, self.attack_family),
            "severity": self.severity,
            "confidence_score": self.confidence,
            "flow_id": {
                "src_ip": self.src_ip,
                "dst_ip": self.dst_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "protocol": self.protocol,
            },
            "evidence": {
                "features": {**self.features,
                             "pkt_count": self.pkt_count,
                             "byte_count": self.byte_count,
                             "duration_s": round(self.duration_s, 3)},
                "explanation": self.explanation or f"Dataset replay: {self.attack_family} detected by {self.generator}",
            },
            "related_alert_ids": [],
            "_source": "dataset_replay",
            "_generator": self.generator,
        }


class DataSource(abc.ABC):
    """Abstract base for all data sources feeding the NOC dashboard."""

    @abc.abstractmethod
    def start(self, scenario: str = "random", duration: Optional[float] = None) -> None:
        """Begin producing data (starts background threads/processes)."""

    @abc.abstractmethod
    def stop(self) -> None:
        """Halt production, clean up resources."""

    @abc.abstractmethod
    def is_running(self) -> bool:
        """Return True while producing data."""

    @abc.abstractmethod
    def read_alerts(self, since_ts: float) -> List[dict]:
        """Return new alert dicts with timestamp > since_ts."""

    @abc.abstractmethod
    def read_telemetry(self) -> dict:
        """Return current telemetry snapshot."""
