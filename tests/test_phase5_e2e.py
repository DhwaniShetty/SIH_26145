import os
import sys
import time
import json
import queue
import random
import argparse
import warnings
from typing import Optional

# We stripped pandas for speed, so we pass numpy arrays to models trained on dataframes.
# This silences the harmless "X does not have valid feature names" warnings from sklearn/LGBM.
warnings.simplefilter('ignore', UserWarning)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingest.pcap_reader import BoundedPcapReader
from parsers.ip_tcp_udp import parse_packet
from parsers.dns_parser import parse_dns
from parsers.tls_quic_handshake import parse_tls_handshake
from features.scheduler import FeatureScheduler

from models.ddos_detector import DDoSDetector
from models.beaconing_detector import BeaconingDetector
from models.dga_classifier import DGAClassifier
from models.encrypted_traffic_classifier import EncryptedTrafficClassifier
from models.recon_scan_detector import ReconScanDetector
from models.exfiltration_detector import ExfiltrationDetector
from models.dns_exfil_detector import DNSExfiltrationDetector

from alerting.normalizer import AlertNormalizer
from alerting.correlator import AlertCorrelator
from alerting.store import AlertStore

SCENARIO_PROFILES = {
    "massive_ddos": {
        "name": "Massive Volumetric DDoS Wave (Thousands of alerts, 0 C2)",
        "plan": [
            ("benign.pcap", 150),
            ("syn_flood.pcap", 2500),
            ("udp_amplification.pcap", 1500)
        ]
    },
    "stealth_c2_exfil": {
        "name": "Stealthy C2 & DNS Exfiltration (0 DDoS)",
        "plan": [
            ("benign.pcap", 300),
            ("c2_beacon.pcap", 60),
            ("dns_tunnel.pcap", 60),
            ("port_scan_horizontal.pcap", 25)
        ]
    },
    "recon_storm": {
        "name": "Reconnaissance Scan Storm (0 DDoS, 0 C2)",
        "plan": [
            ("benign.pcap", 200),
            ("port_scan_vertical.pcap", 300),
            ("port_scan_hybrid.pcap", 200)
        ]
    },
    "quiet_hours": {
        "name": "Calm Baseline (0 DDoS, 0 C2, ~0 threats)",
        "plan": [
            ("benign.pcap", 400)
        ]
    },
    "coordinated_campaign": {
        "name": "Coordinated Multi-Vector Attack Campaign",
        "plan": [
            ("benign.pcap", 200),
            ("port_scan_horizontal.pcap", 80),
            ("c2_beacon.pcap", 50),
            ("dns_tunnel.pcap", 50),
            ("syn_flood.pcap", 1500)
        ]
    }
}

def generate_random_scenario():
    """Generates a dynamic, highly varied attack scenario where threats fluctuate wildly."""
    plan = [("benign.pcap", random.randint(150, 350))]
    
    # Independent coin flips for each attack vector
    has_ddos = random.random() < 0.55
    has_c2 = random.random() < 0.50
    has_recon = random.random() < 0.55
    has_dns = random.random() < 0.45
    
    # Guarantee at least one attack so the dashboard doesn't start empty
    if not any([has_ddos, has_c2, has_recon, has_dns]):
        has_ddos = True
        has_recon = True
    
    desc_parts = []
    
    if has_ddos:
        # DDoS can be moderate (600-1200) or massive (2000-3500)
        ddos_count = random.choice([random.randint(600, 1200), random.randint(2000, 3500)])
        ddos_pcap = random.choice(["syn_flood.pcap", "udp_amplification.pcap"])
        plan.append((ddos_pcap, ddos_count))
        desc_parts.append(f"DDoS ({ddos_count} pkts)")
    else:
        desc_parts.append("0 DDoS")
        
    if has_c2:
        c2_count = random.randint(25, 80)
        plan.append(("c2_beacon.pcap", c2_count))
        desc_parts.append(f"C2 Beacon ({c2_count} pkts)")
    else:
        desc_parts.append("0 C2")
        
    if has_recon:
        recon_count = random.randint(40, 250)
        recon_pcap = random.choice(["port_scan_horizontal.pcap", "port_scan_vertical.pcap", "port_scan_hybrid.pcap"])
        plan.append((recon_pcap, recon_count))
        desc_parts.append(f"Recon ({recon_count} pkts)")
    else:
        desc_parts.append("0 Recon")
        
    if has_dns:
        dns_count = random.randint(25, 75)
        plan.append(("dns_tunnel.pcap", dns_count))
        desc_parts.append(f"DNS Exfil ({dns_count} pkts)")
    else:
        desc_parts.append("0 DNS Exfil")
        
    name = "Dynamic Mix: " + ", ".join(desc_parts)
    return {"name": name, "plan": plan}

def update_telemetry(pkts_rate, mbps, active_flows, latency_ms, status="STREAMING"):
    telemetry_path = os.path.join(os.path.dirname(__file__), 'telemetry.json')
    data = {
        "pkts_per_sec": int(pkts_rate),
        "mbps": round(float(mbps), 1),
        "active_flows": int(active_flows),
        "latency_ms": round(float(latency_ms), 2),
        "diode_mode": "PASSIVE RX ONLY (Tx Physically Disabled)",
        "status": status,
        "updated_at": time.time()
    }
    try:
        tmp_path = telemetry_path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, telemetry_path)
    except Exception:
        pass

import signal

def run_e2e_pipeline(scenario: str = "random", duration: Optional[float] = None):
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    data_dir = os.path.join(root_dir, 'data')
    results_dir = os.path.join(root_dir, 'models', 'train', 'results')
    
    stop_flag = False
    def handle_stop(signum, frame):
        nonlocal stop_flag
        stop_flag = True

    try:
        signal.signal(signal.SIGINT, handle_stop)
        signal.signal(signal.SIGTERM, handle_stop)
    except Exception:
        pass

    # Resolve scenario plan
    if scenario in SCENARIO_PROFILES:
        profile = SCENARIO_PROFILES[scenario]
    else:
        profile = generate_random_scenario()
        
    dur_label = f" (Duration: {duration}s)" if duration else ""
    print(f"\n[SCENARIO] Running: {profile['name']}{dur_label}")
    plan = profile["plan"]
    
    # Initialize Detectors
    detectors = {
        "ddos": DDoSDetector(os.path.join(results_dir, 'ddos_lgbm.pkl')),
        "beaconing": BeaconingDetector(os.path.join(results_dir, 'beaconing_ocsvm.pkl')),
        "dga": DGAClassifier(
            gbt_model_path=os.path.join(results_dir, 'dga_gbt.pkl'),
            lstm_model_path=os.path.join(results_dir, 'dga_lstm.pt')
        ),
        "encrypted": EncryptedTrafficClassifier(os.path.join(results_dir, 'encrypted_rf.pkl')),
        "recon": ReconScanDetector(os.path.join(results_dir, 'recon_iso.pkl')),
        "exfil": ExfiltrationDetector(os.path.join(results_dir, 'exfil_iso.pkl')),
        "dns_exfil": DNSExfiltrationDetector()
    }
    
    # Initialize Alerting subsystems
    db_path = os.path.join(os.path.dirname(__file__), 'test_alerts.db')
    normalizer = AlertNormalizer()
    correlator = AlertCorrelator(time_window_seconds=600)
    store = AlertStore(db_path=db_path, batch_size=50)
    store.clear()
    
    scheduler = FeatureScheduler(window_1s=0.1, window_5s=0.5, window_60s=1.0)
    
    total_pkts = 0
    total_bytes = 0
    distinct_flows = set()
    latencies = []
    t_start = time.perf_counter()
    sim_clock = time.time()
    prev_raw_ts = None
    running = True

    while running and not stop_flag:
        for pcap_file, target_count in plan:
            if stop_flag or (duration and (time.perf_counter() - t_start >= duration)):
                running = False
                break

            pcap_path = os.path.join(data_dir, pcap_file)
            if not os.path.exists(pcap_path):
                print(f"Skipping {pcap_file}, not found.")
                continue

            # Ingest packets from PCAP once into memory for fast zero-overhead streaming
            raw_packets = []
            reader = BoundedPcapReader(pcap_path, max_buffer_size=10000)
            reader.start()
            while True:
                try:
                    item = reader.get_packet(timeout=0.005)
                    if item[0] is None:
                        break
                    raw_packets.append(item)
                except queue.Empty:
                    break
            reader.stop()

            if not raw_packets:
                continue

            print(f"Ingesting {pcap_file} (target: {target_count} pkts, source: {len(raw_packets)} pkts)...")
            pkts_processed = 0
            pcap_idx = 0
            n_pkts = len(raw_packets)

            while pkts_processed < target_count:
                if stop_flag or (duration and (time.perf_counter() - t_start >= duration)):
                    running = False
                    break

                raw_ts, buf = raw_packets[pcap_idx % n_pkts]
                pcap_idx += 1
                pkts_processed += 1
                total_pkts += 1
                total_bytes += len(buf)

                # Monotonic time progression preserving realistic packet inter-arrival times
                if prev_raw_ts is None:
                    dt = 0.001
                else:
                    raw_diff = raw_ts - prev_raw_ts
                    dt = 0.001 if (raw_diff <= 0 or raw_diff > 2.0) else raw_diff
                sim_clock += dt
                prev_raw_ts = raw_ts
                ts = sim_clock

                t_pkt_0 = time.perf_counter()

                meta = parse_packet(buf)
                if not meta:
                    continue

                distinct_flows.add((meta.get('src_ip'), meta.get('dst_ip'), meta.get('dst_port')))

                dns_parsed = None
                if meta['protocol'] == 'UDP' and (meta['dst_port'] == 53 or meta['src_port'] == 53):
                    dns_parsed = parse_dns(meta['payload'])

                tls_parsed = None
                if meta['protocol'] == 'TCP' and (meta['dst_port'] == 443 or meta['src_port'] == 443):
                    tls_parsed = parse_tls_handshake(meta['payload'])

                fired_features = scheduler.process_packet(meta, ts, dns_parsed, tls_parsed)
                if fired_features:
                    for det_name, feats in fired_features.items():
                        det_model = detectors.get(det_name)
                        if not det_model:
                            continue
                        score, feats_used, expl = det_model.predict(feats)
                        if expl and score > 0.5:
                            alert = normalizer.normalize(
                                detector_name=det_name,
                                raw_score=score,
                                feature_values=feats_used,
                                explanation=expl,
                                flow_info=meta,
                                timestamp=ts
                            )
                            correlated_alert = correlator.process(alert)
                            store.append(correlated_alert)

                latencies.append(time.perf_counter() - t_pkt_0)

                # Periodically write telemetry snapshot for dashboard stream
                if total_pkts % 200 == 0:
                    elapsed = max(0.001, time.perf_counter() - t_start)
                    pps = total_pkts / elapsed
                    mbps = (total_bytes * 8) / (elapsed * 1_000_000)
                    cur_lat = (sum(latencies[-50:]) / max(1, len(latencies[-50:]))) * 1000
                    update_telemetry(pps, mbps, len(distinct_flows), cur_lat, status="STREAMING")

        if not duration or (time.perf_counter() - t_start >= duration):
            break

    store.flush()
    alerts = store.read_alerts()
    elapsed = max(0.001, time.perf_counter() - t_start)
    final_pps = total_pkts / elapsed
    final_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
    final_lat = (sum(latencies) / max(1, len(latencies))) * 1000 if latencies else 1.2
    update_telemetry(final_pps, final_mbps, len(distinct_flows), final_lat, status="IDLE_BASELINE")

    status_msg = "[STOPPED]" if stop_flag else "[DONE]"
    print(f"\n{status_msg} Replay finished in {elapsed:.1f}s. Total alerts in store: {len(alerts)}")
    print(f"Throughput: {final_pps:.0f} pkts/s | {final_mbps:.1f} Mbps | Latency: {final_lat:.2f}ms")
    
    correlated_examples = [a for a in alerts if len(a.related_alert_ids) > 0]
    print(f"Correlated alerts found: {len(correlated_examples)}")
    store.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="E2E Pipeline Replay")
    parser.add_argument("--scenario", "-s", type=str, default="random", 
                        choices=["random", "massive_ddos", "stealth_c2_exfil", "recon_storm", "quiet_hours", "coordinated_campaign"],
                        help="Attack scenario to replay")
    parser.add_argument("--duration", "-d", type=float, default=None,
                        help="Replay duration in seconds (continuous loop until expired)")
    args = parser.parse_args()
    run_e2e_pipeline(scenario=args.scenario, duration=args.duration)
