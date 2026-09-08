import random
import os
import time
from scapy.all import IP, TCP
from common import save_pcap_and_labels, get_base_labels

def generate_syn_flood(target_ip, target_port, num_packets=1000):
    packets = []
    labels = get_base_labels("SYN_FLOOD", "Simulated TCP SYN flood attack")
    
    start_time = time.time()
    
    for i in range(num_packets):
        src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        
        pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        pkt.time = start_time + (i * 0.001)  # Simulate 1000 packets per second
        packets.append(pkt)
        
        labels["flows"].append({
            "src_ip": src_ip,
            "dst_ip": target_ip,
            "src_port": src_port,
            "dst_port": target_port,
            "protocol": "TCP",
            "is_attack": True,
            "timestamp": pkt.time
        })
        
    return packets, labels

if __name__ == "__main__":
    target = "192.168.1.100"
    port = 80
    pkts, lbls = generate_syn_flood(target, port)
    save_pcap_and_labels("syn_flood.pcap", pkts, lbls, out_dir=os.path.join(os.path.dirname(__file__), "../../data/"))
