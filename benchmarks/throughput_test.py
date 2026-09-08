import os
import sys
import time
import queue
import psutil
import threading

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

from alerting.normalizer import AlertNormalizer
from alerting.correlator import AlertCorrelator

def run_throughput_test():
    pcap_path = os.path.join(os.path.dirname(__file__), '../data/syn_flood.pcap')
    if not os.path.exists(pcap_path):
        print(f"File {pcap_path} not found. Ensure Phase 1 data is generated.")
        return
        
    pcap_size_bytes = os.path.getsize(pcap_path)
    pcap_size_mb = pcap_size_bytes / (1024 * 1024)
    
    results_dir = os.path.join(os.path.dirname(__file__), '../models/train/results')
    
    print("Loading models (this doesn't count towards throughput time)...")
    detectors = {
        "ddos": DDoSDetector(os.path.join(results_dir, 'ddos_lgbm.pkl')),
        "beaconing": BeaconingDetector(os.path.join(results_dir, 'beaconing_ocsvm.pkl')),
        "dga": DGAClassifier(
            gbt_model_path=os.path.join(results_dir, 'dga_gbt.pkl'),
            lstm_model_path=os.path.join(results_dir, 'dga_lstm.pt')
        ),
        "encrypted": EncryptedTrafficClassifier(os.path.join(results_dir, 'encrypted_rf.pkl')),
        "recon": ReconScanDetector(os.path.join(results_dir, 'recon_iso.pkl')),
        "exfil": ExfiltrationDetector(os.path.join(results_dir, 'exfil_iso.pkl'))
    }
    
    normalizer = AlertNormalizer()
    correlator = AlertCorrelator(time_window_seconds=600)
    scheduler = FeatureScheduler(window_1s=0.1, window_5s=0.5, window_60s=1.0)
    
    reader = BoundedPcapReader(pcap_path, max_buffer_size=50000)
    
    proc = psutil.Process(os.getpid())
    
    print(f"Starting throughput test on {pcap_size_mb:.2f} MB PCAP...")
    
    reader.start()
    
    start_time = time.time()
    packet_count = 0
    alerts_generated = 0
    
    cpu_measurements = []
    mem_measurements = []
    
    # We poll psutil in a separate thread so it doesn't block processing
    stop_stats = threading.Event()
    def stats_poller():
        while not stop_stats.is_set():
            try:
                cpu_measurements.append(proc.cpu_percent(interval=None))
                mem_measurements.append(proc.memory_info().rss / (1024 * 1024))
            except:
                pass
            time.sleep(0.1)
            
    stats_thread = threading.Thread(target=stats_poller, daemon=True)
    stats_thread.start()
    
    while True:
        try:
            ts, buf = reader.get_packet(timeout=1.0)
            if ts is None:
                break
            
            packet_count += 1
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
            
            for det_name, det_model in detectors.items():
                if det_name in f:
                    score, feats_used, expl = det_model.predict(f[det_name])
                    if expl and score > 0.5:
                        alert = normalizer.normalize(det_name, score, feats_used, expl, meta, ts)
                        correlator.process(alert)
                        # We bypass writing to sqlite to isolate processing throughput
                        alerts_generated += 1
                        
        except queue.Empty:
            # If reader is stopped and queue is empty, we break
            break
            
    end_time = time.time()
    stop_stats.set()
    stats_thread.join()
    reader.stop()
    
    duration = end_time - start_time
    packets_per_sec = packet_count / duration
    mbps = (pcap_size_mb * 8) / duration  # Megabits per second
    
    avg_cpu = sum(cpu_measurements) / len(cpu_measurements) if cpu_measurements else 0
    avg_mem = sum(mem_measurements) / len(mem_measurements) if mem_measurements else 0
    
    print("\n--- Throughput & Resource Footprint Results ---")
    print(f"Total packets processed : {packet_count}")
    print(f"Alerts generated        : {alerts_generated}")
    print(f"Total time              : {duration:.2f} seconds")
    print(f"Throughput (Packets/s)  : {packets_per_sec:.2f} pps")
    print(f"Throughput (Mbps)       : {mbps:.2f} Mbps")
    print(f"Average CPU Usage       : {avg_cpu:.1f}%")
    print(f"Average Memory (RSS)    : {avg_mem:.1f} MB")
    print(f"Queue Drops             : {reader.dropped_packets}")

if __name__ == "__main__":
    run_throughput_test()
