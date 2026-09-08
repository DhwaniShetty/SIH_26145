import os
import sys
import queue

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

def run_e2e_pipeline():
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data'))
    results_dir = os.path.join(os.path.dirname(__file__), '../models/train/results')
    
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
        "dns_exfil": DNSExfiltrationDetector() # using heuristic for testing
    }
    
    # Initialize Alerting subsystems
    db_path = os.path.join(os.path.dirname(__file__), 'test_alerts.db')
    if os.path.exists(db_path):
        os.remove(db_path)
        
    normalizer = AlertNormalizer()
    correlator = AlertCorrelator(time_window_seconds=600)  # 10 minutes to ensure correlation across pcaps
    store = AlertStore(db_path=db_path)
    
    # Replay PCAPs chronologically to simulate a mixed environment
    # We use recon -> beaconing to trigger a correlation specifically (same source IP is typically used in our synthetic generation scripts)
    pcaps = ["port_scan_horizontal.pcap", "c2_beacon.pcap", "syn_flood.pcap"]
    
    scheduler = FeatureScheduler(window_1s=0.1, window_5s=0.5, window_60s=1.0)
    
    print("Starting E2E Replay...")
    
    for pcap_file in pcaps:
        pcap_path = os.path.join(data_dir, pcap_file)
        if not os.path.exists(pcap_path):
            print(f"Skipping {pcap_file}, not found.")
            continue
            
        print(f"Ingesting {pcap_file}...")
        reader = BoundedPcapReader(pcap_path, max_buffer_size=10000)
        reader.start()
        
        while True:
            try:
                ts, buf = reader.get_packet()
                if ts is None:
                    break
                
                meta = parse_packet(buf)
                if not meta:
                    continue
                    
                dns_parsed = None
                if meta['protocol'] == 'UDP' and (meta['dst_port'] == 53 or meta['src_port'] == 53):
                    dns_parsed = parse_dns(meta['payload'])
                    
                tls_parsed = None
                if meta['protocol'] == 'TCP' and (meta['dst_port'] == 443 or meta['src_port'] == 443):
                    tls_parsed = parse_tls_handshake(meta['payload'])
                    
                scheduler.process_packet(meta, ts, dns_parsed, tls_parsed)
                
                f = scheduler.extract_all(meta['src_ip'], meta['dst_ip'])
                
                # Inference and Alerting
                for det_name, det_model in detectors.items():
                    if det_name in f:
                        score, feats_used, expl = det_model.predict(f[det_name])
                        
                        # Only alert if score is high enough and there is an explanation
                        if expl and score > 0.5:
                            # Normalize
                            alert = normalizer.normalize(
                                detector_name=det_name,
                                raw_score=score,
                                feature_values=feats_used,
                                explanation=expl,
                                flow_info=meta,
                                timestamp=ts
                            )
                            
                            # Correlate
                            correlated_alert = correlator.process(alert)
                            
                            # Store
                            store.append(correlated_alert)
                
            except queue.Empty:
                continue
                
        reader.stop()
        
    print("E2E Replay completed.")
    
    # Verify Exit Criteria
    alerts = store.read_alerts()
    print(f"Total alerts generated: {len(alerts)}")
    assert len(alerts) > 0, "No alerts were generated!"
    
    correlated_examples = [a for a in alerts if len(a.related_alert_ids) > 0]
    print(f"Correlated alerts found: {len(correlated_examples)}")
    
    if correlated_examples:
        print("\n--- Example of Correlated Alert ---")
        example = correlated_examples[-1] # take a recent one
        print(f"Alert ID: {example.alert_id}")
        print(f"Detector: {example.detector} ({example.severity})")
        print(f"Explanation: {example.evidence.explanation}")
        print(f"Flow: {example.flow_id.src_ip} -> {example.flow_id.dst_ip}")
        print(f"Related Alert IDs: {example.related_alert_ids}")
        
        # Fetch related alert
        related_id = example.related_alert_ids[0]
        related_alerts = [a for a in alerts if a.alert_id == related_id]
        if related_alerts:
            rel = related_alerts[0]
            print(f"  -> Links to {rel.detector} alert: {rel.evidence.explanation} for Flow {rel.flow_id.src_ip} -> {rel.flow_id.dst_ip}")
            
    print("\nPhase 5 End-to-End tests passed.")

if __name__ == "__main__":
    run_e2e_pipeline()
