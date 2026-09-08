import random
import os
import time
from scapy.all import IP, TCP
from common import save_pcap_and_labels, get_base_labels

def generate_c2_beacon(src_ip, c2_ip, interval=10, jitter=0.1, num_beacons=50):
    packets = []
    labels = get_base_labels("C2_BEACONING", "Simulated periodic C2 beaconing")
    
    current_time = time.time()
    
    for _ in range(num_beacons):
        # Add jitter
        actual_interval = interval * (1 + random.uniform(-jitter, jitter))
        current_time += actual_interval
        
        src_port = random.randint(10000, 60000)
        dst_port = 443
        
        # Simulate SYN to C2
        pkt = IP(src=src_ip, dst=c2_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
        pkt.time = current_time
        
        packets.append(pkt)
        
        labels["flows"].append({
            "src_ip": src_ip,
            "dst_ip": c2_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP",
            "is_attack": True,
            "timestamp": pkt.time
        })
        
    return packets, labels

if __name__ == "__main__":
    src = "10.0.0.50"
    c2 = "198.51.100.200"
    pkts, lbls = generate_c2_beacon(src, c2, interval=5, jitter=0.2)
    save_pcap_and_labels("c2_beacon.pcap", pkts, lbls, out_dir=os.path.join(os.path.dirname(__file__), "../../data/"))
