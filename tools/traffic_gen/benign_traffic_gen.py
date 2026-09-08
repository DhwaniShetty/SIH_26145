import os
import random
import time
from scapy.all import IP, TCP, UDP, DNS, DNSQR
from common import save_pcap_and_labels, get_base_labels

def generate_benign_traffic(num_packets=1000):
    packets = []
    labels = get_base_labels("BENIGN", "Normal user web browsing and DNS")
    
    start_time = time.time()
    
    # Simulate normal user LAN
    clients = [f"192.168.1.{i}" for i in range(100, 150)]
    dns_server = "8.8.8.8"
    
    # Common benign domains
    domains = ["google.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com"]
    
    for i in range(num_packets):
        src_ip = random.choice(clients)
        
        # 20% DNS, 80% TCP (HTTP/TLS)
        if random.random() < 0.2:
            domain = random.choice(domains)
            src_port = random.randint(10000, 60000)
            pkt = IP(src=src_ip, dst=dns_server) / UDP(sport=src_port, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            pkt.time = start_time + (i * 0.05)
            packets.append(pkt)
            labels["flows"].append({
                "src_ip": src_ip, "dst_ip": dns_server, "protocol": "UDP", "is_attack": False
            })
        else:
            dst_ip = f"104.21.3.{random.randint(1, 200)}"
            src_port = random.randint(10000, 60000)
            
            # Simple TCP SYN (we could build full TLS ClientHello but a simple TCP packet is enough 
            # to provide benign baseline metrics for IAT, cardinality, out/in ratio, etc.)
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=443, flags="PA")
            # add some dummy payload length to make it look like data
            pkt = pkt / ("A" * random.randint(100, 1000))
            pkt.time = start_time + (i * 0.05)
            packets.append(pkt)
            labels["flows"].append({
                "src_ip": src_ip, "dst_ip": dst_ip, "protocol": "TCP", "is_attack": False
            })
            
    return packets, labels

if __name__ == "__main__":
    pkts, lbls = generate_benign_traffic()
    save_pcap_and_labels("benign.pcap", pkts, lbls, out_dir=os.path.join(os.path.dirname(__file__), "../../data/"))
