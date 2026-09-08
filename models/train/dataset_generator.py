import os
import sys
import json
import queue
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from ingest.pcap_reader import BoundedPcapReader
from parsers.ip_tcp_udp import parse_packet
from parsers.dns_parser import parse_dns
from parsers.tls_quic_handshake import parse_tls_handshake
from features.scheduler import FeatureScheduler

def extract_features_to_df(pcap_path, is_attack, attack_type=None):
    if not os.path.exists(pcap_path):
        return pd.DataFrame()
        
    reader = BoundedPcapReader(pcap_path, max_buffer_size=10000)
    scheduler = FeatureScheduler(window_1s=0.1, window_5s=0.5, window_60s=1.0)
    
    reader.start()
    
    records = []
    
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
            
            record = {
                "timestamp": ts,
                "src_ip": meta['src_ip'],
                "dst_ip": meta['dst_ip'],
                "is_attack": int(is_attack),
                "attack_type": attack_type if is_attack else "Benign"
            }
            
            # Flatten features
            if f.get('ddos'):
                for k, v in f['ddos'].items(): record[f"ddos_{k}"] = v
            if f.get('beaconing'):
                for k, v in f['beaconing'].items(): record[f"beacon_{k}"] = v
            if f.get('dga'):
                for k, v in f['dga'].items(): record[f"dga_{k}"] = v
            if f.get('recon'):
                for k, v in f['recon'].items(): record[f"recon_{k}"] = v
            if f.get('exfil'):
                for k, v in f['exfil'].items(): record[f"exfil_{k}"] = v
            if f.get('encrypted'):
                record["tls_sni_length"] = f['encrypted'].get('sni_length_ewma', 0)
                
            records.append(record)
            
        except queue.Empty:
            continue
            
    reader.stop()
    return pd.DataFrame(records)

def build_dataset():
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data'))
    
    benign_df = extract_features_to_df(os.path.join(data_dir, 'benign.pcap'), False)
    ddos_df = extract_features_to_df(os.path.join(data_dir, 'syn_flood.pcap'), True, "DDoS")
    beacon_df = extract_features_to_df(os.path.join(data_dir, 'c2_beacon.pcap'), True, "Beaconing")
    dga_df = extract_features_to_df(os.path.join(data_dir, 'dns_tunnel.pcap'), True, "DGA")
    
    # Optional scan and exfil (if generated, otherwise use what we have)
    
    df = pd.concat([benign_df, ddos_df, beacon_df, dga_df], ignore_index=True)
    return df

if __name__ == "__main__":
    df = build_dataset()
    out_path = os.path.join(os.path.dirname(__file__), 'training_data.csv')
    df.to_csv(out_path, index=False)
    print(f"Generated dataset with {len(df)} records at {out_path}")
