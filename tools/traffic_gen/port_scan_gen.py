import random
import os
import time
from scapy.all import IP, TCP
from common import save_pcap_and_labels, get_base_labels

def generate_port_scan(src_ip, target_network="192.168.1.", scan_type="horizontal", num_targets=50):
    """
    scan_type: "horizontal" (many IPs, one port), "vertical" (one IP, many ports), "hybrid" (many IPs, many ports)
    """
    packets = []
    labels = get_base_labels("PORT_SCAN", f"Simulated {scan_type} port scan")
    
    current_time = time.time()
    
    if scan_type == "horizontal":
        dst_port = 22
        for i in range(1, num_targets + 1):
            dst_ip = f"{target_network}{i}"
            src_port = random.randint(10000, 60000)
            
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
            pkt.time = current_time + (i * 0.01)
            packets.append(pkt)
            
            labels["flows"].append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                "protocol": "TCP", "is_attack": True, "timestamp": pkt.time
            })
            
    elif scan_type == "vertical":
        dst_ip = f"{target_network}10"
        for i, dst_port in enumerate(range(1, 1024)):
            src_port = random.randint(10000, 60000)
            
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
            pkt.time = current_time + (i * 0.005)
            packets.append(pkt)
            
            labels["flows"].append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                "protocol": "TCP", "is_attack": True, "timestamp": pkt.time
            })
            
    elif scan_type == "hybrid":
        for i in range(1, 10):
            dst_ip = f"{target_network}{i}"
            for j, dst_port in enumerate([22, 80, 443, 3389, 8080]):
                src_port = random.randint(10000, 60000)
                
                pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
                pkt.time = current_time + (i * 0.05) + (j * 0.01)
                packets.append(pkt)
                
                labels["flows"].append({
                    "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                    "protocol": "TCP", "is_attack": True, "timestamp": pkt.time
                })

    return packets, labels

if __name__ == "__main__":
    src = "10.0.0.50"
    
    for s_type in ["horizontal", "vertical", "hybrid"]:
        pkts, lbls = generate_port_scan(src, scan_type=s_type)
        save_pcap_and_labels(f"port_scan_{s_type}.pcap", pkts, lbls, out_dir=os.path.join(os.path.dirname(__file__), "../../data/"))
