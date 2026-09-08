import random
import os
import time
from scapy.all import IP, UDP, DNS, DNSQR
from common import save_pcap_and_labels, get_base_labels

def generate_udp_amplification(target_ip, num_packets=500):
    packets = []
    labels = get_base_labels("UDP_AMPLIFICATION", "Simulated UDP DNS amplification attack")
    
    # List of open resolvers (simulated)
    resolvers = [f"8.8.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(10)]
    start_time = time.time()
    
    for i in range(num_packets):
        # The attacker spoofs the source IP to be the target's IP
        resolver = random.choice(resolvers)
        
        # Simulating the amplified response from the resolver to the target
        # In a real reflection, we'd see the request from the attacker to the resolver with spoofed source,
        # but here we simulate the response hitting the target.
        # Since it's unidirectional traffic hitting the target network, we see the responses.
        
        pkt = IP(src=resolver, dst=target_ip) / UDP(sport=53, dport=random.randint(1024, 65535)) / DNS(qr=1, ancount=50) 
        # Large payload to simulate amplification
        pkt = pkt / ("A" * 1024)
        pkt.time = start_time + (i * 0.002)
        
        packets.append(pkt)
        
        labels["flows"].append({
            "src_ip": resolver,
            "dst_ip": target_ip,
            "src_port": 53,
            "dst_port": pkt[UDP].dport,
            "protocol": "UDP",
            "is_attack": True,
            "timestamp": pkt.time
        })
        
    return packets, labels

if __name__ == "__main__":
    target = "192.168.1.100"
    pkts, lbls = generate_udp_amplification(target)
    save_pcap_and_labels("udp_amplification.pcap", pkts, lbls, out_dir=os.path.join(os.path.dirname(__file__), "../../data/"))
