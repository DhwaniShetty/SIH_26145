import os
import sys
import time
import queue
import numpy as np

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingest.pcap_reader import BoundedPcapReader
from parsers.ip_tcp_udp import parse_packet
from parsers.dns_parser import parse_dns
from parsers.tls_quic_handshake import parse_tls_handshake
from features.scheduler import FeatureScheduler

from models.ddos_detector import DDoSDetector
from models.recon_scan_detector import ReconScanDetector
from alerting.normalizer import AlertNormalizer

def measure_latency():
    # We will measure latency for DDoS on syn_flood.pcap
    pcap_path = os.path.join(os.path.dirname(__file__), '../data/syn_flood.pcap')
    results_dir = os.path.join(os.path.dirname(__file__), '../models/train/results')
    
    det = DDoSDetector(os.path.join(results_dir, 'ddos_lgbm.pkl'))
    normalizer = AlertNormalizer()
    scheduler = FeatureScheduler()
    
    reader = BoundedPcapReader(pcap_path, max_buffer_size=50000)
    reader.start()
    
    latencies = []
    
    while True:
        try:
            ts, buf = reader.get_packet(timeout=0.5)
            if ts is None:
                break
                
            wall_start = time.time()
            
            meta = parse_packet(buf)
            if not meta:
                continue
                
            scheduler.process_packet(meta, ts, None, None)
            f = scheduler.extract_all(meta['src_ip'], meta['dst_ip'])
            
            if "ddos" in f:
                score, feats, expl = det.predict(f["ddos"])
                if expl and score > 0.5:
                    alert = normalizer.normalize("ddos", score, feats, expl, meta, ts)
                    wall_end = time.time()
                    latencies.append(wall_end - wall_start)
                    
        except queue.Empty:
            break
            
    reader.stop()
    
    if latencies:
        p95 = np.percentile(latencies, 95) * 1000  # in ms
        mean_lat = np.mean(latencies) * 1000
        print("\n--- Latency Measurement (DDoS/SYN Flood) ---")
        print(f"Total alerts evaluated : {len(latencies)}")
        print(f"Mean Latency           : {mean_lat:.2f} ms")
        print(f"95th Percentile        : {p95:.2f} ms")
    else:
        print("No alerts triggered, couldn't measure latency.")

if __name__ == "__main__":
    measure_latency()
