import os
import sys
import queue
import random
import argparse
import warnings

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

def run_e2e_pipeline(scenario: str = "random"):
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data'))
    results_dir = os.path.join(os.path.dirname(__file__), '../models/train/results')
    
    # Resolve scenario plan
    if scenario in SCENARIO_PROFILES:
        profile = SCENARIO_PROFILES[scenario]
    else:
        profile = generate_random_scenario()
        
    print(f"\n[SCENARIO] Running: {profile['name']}")
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
    
    for pcap_file, target_count in plan:
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
            ts, buf = raw_packets[pcap_idx % n_pkts]
            pcap_idx += 1
            pkts_processed += 1

            meta = parse_packet(buf)
            if not meta:
                continue

            dns_parsed = None
            if meta['protocol'] == 'UDP' and (meta['dst_port'] == 53 or meta['src_port'] == 53):
                dns_parsed = parse_dns(meta['payload'])

            tls_parsed = None
            if meta['protocol'] == 'TCP' and (meta['dst_port'] == 443 or meta['src_port'] == 443):
                tls_parsed = parse_tls_handshake(meta['payload'])

            fired_features = scheduler.process_packet(meta, ts, dns_parsed, tls_parsed)
            if not fired_features:
                continue

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
                
    store.flush()
    alerts = store.read_alerts()
    print(f"\n[DONE] Replay finished. Total alerts in store: {len(alerts)}")
    
    correlated_examples = [a for a in alerts if len(a.related_alert_ids) > 0]
    print(f"Correlated alerts found: {len(correlated_examples)}")
    store.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="E2E Pipeline Replay")
    parser.add_argument("--scenario", "-s", type=str, default="random", 
                        choices=["random", "massive_ddos", "stealth_c2_exfil", "recon_storm", "quiet_hours", "coordinated_campaign"],
                        help="Attack scenario to replay")
    args = parser.parse_args()
    run_e2e_pipeline(scenario=args.scenario)
