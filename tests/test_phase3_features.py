import os
import sys
import queue
import matplotlib.pyplot as plt

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingest.pcap_reader import BoundedPcapReader
from parsers.ip_tcp_udp import parse_packet
from parsers.dns_parser import parse_dns
from parsers.tls_quic_handshake import parse_tls_handshake
from features.scheduler import FeatureScheduler

def extract_features_from_pcap(pcap_path):
    if not os.path.exists(pcap_path):
        return None
        
    reader = BoundedPcapReader(pcap_path, max_buffer_size=10000)
    scheduler = FeatureScheduler(window_1s=0.1, window_5s=0.5, window_60s=1.0) # Compressed time
    
    reader.start()
    
    features_list = []
    
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
            
            # For testing, directly grab latest features
            f = scheduler.extract_all(meta['src_ip'], meta['dst_ip'])
            features_list.append(f)
            
        except queue.Empty:
            continue
            
    reader.stop()
    return features_list

def plot_features():
    base_dir = os.path.dirname(__file__)
    data_dir = os.path.join(base_dir, '../data')
    
    benign_pcap = os.path.join(data_dir, 'benign.pcap')
    attack_pcap = os.path.join(data_dir, 'syn_flood.pcap')
    beacon_pcap = os.path.join(data_dir, 'c2_beacon.pcap')
    dns_pcap = os.path.join(data_dir, 'dns_tunnel.pcap')
    
    print("Extracting features from Benign traffic...")
    benign_f = extract_features_from_pcap(benign_pcap)
    print("Extracting features from SYN Flood traffic...")
    ddos_f = extract_features_from_pcap(attack_pcap)
    print("Extracting features from Beaconing traffic...")
    beacon_f = extract_features_from_pcap(beacon_pcap)
    print("Extracting features from DNS Tunnel traffic...")
    dga_f = extract_features_from_pcap(dns_pcap)
    
    if not all([benign_f, ddos_f, beacon_f, dga_f]):
        print("Missing PCAP files. Ensure Phase 1 generators ran.")
        return
        
    plt.figure(figsize=(15, 10))
    
    # Plot 1: DDoS (SYN ratio)
    plt.subplot(2, 2, 1)
    b_syn = [f['ddos']['syn_synack_ratio'] for f in benign_f if f['ddos']]
    a_syn = [f['ddos']['syn_synack_ratio'] for f in ddos_f if f['ddos']]
    plt.hist(b_syn, alpha=0.5, label='Benign', bins=20)
    plt.hist(a_syn, alpha=0.5, label='SYN Flood', bins=20)
    plt.title('DDoS: SYN Ratio')
    plt.legend()
    
    # Plot 2: Beaconing (IAT CV)
    plt.subplot(2, 2, 2)
    b_cv = [f['beaconing']['iat_cv'] for f in benign_f if f['beaconing'] and f['beaconing']['iat_cv'] > 0]
    a_cv = [f['beaconing']['iat_cv'] for f in beacon_f if f['beaconing'] and f['beaconing']['iat_cv'] > 0]
    if b_cv: plt.hist(b_cv, alpha=0.5, label='Benign', bins=10)
    if a_cv: plt.hist(a_cv, alpha=0.5, label='Beaconing', bins=10)
    plt.title('C2 Beaconing: IAT Coefficient of Variation')
    plt.legend()
    
    # Plot 3: DNS Tunnel (Query Length)
    plt.subplot(2, 2, 3)
    b_len = [f['dga']['avg_query_length'] for f in benign_f if f['dga'] and f['dga']['avg_query_length'] > 0]
    a_len = [f['dga']['avg_query_length'] for f in dga_f if f['dga'] and f['dga']['avg_query_length'] > 0]
    if b_len: plt.hist(b_len, alpha=0.5, label='Benign', bins=10)
    if a_len: plt.hist(a_len, alpha=0.5, label='DNS Tunnel', bins=10)
    plt.title('DGA: Avg DNS Query Length')
    plt.legend()
    
    # Plot 4: Recon (SYN Only Ratio)
    plt.subplot(2, 2, 4)
    b_recon = [f['recon']['syn_only_ratio'] for f in benign_f if f['recon']]
    a_recon = [f['recon']['syn_only_ratio'] for f in ddos_f if f['recon']] # using syn flood as proxy for high syn-only
    plt.hist(b_recon, alpha=0.5, label='Benign', bins=20)
    plt.hist(a_recon, alpha=0.5, label='Scanner/Flood', bins=20)
    plt.title('Recon: SYN Only Ratio')
    plt.legend()
    
    plt.tight_layout()
    out_path = os.path.join(base_dir, 'feature_separation.png')
    plt.savefig(out_path)
    print(f"Saved plots to {out_path}")
    
if __name__ == "__main__":
    plot_features()
