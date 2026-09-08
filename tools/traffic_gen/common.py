import json
import os
import time

def save_pcap_and_labels(pcap_filename, packets, labels, out_dir="."):
    """
    Saves a list of packets to a PCAP file and their corresponding labels to a JSON file.
    
    Args:
        pcap_filename (str): The output pcap filename (e.g., 'syn_flood.pcap').
        packets (list): List of Scapy packets.
        labels (dict): Dictionary representing ground truth labels.
        out_dir (str): Directory to save the files.
    """
    try:
        from scapy.all import wrpcap
    except ImportError:
        print("Scapy is required to run traffic generators. Install it with: pip install scapy")
        return

    os.makedirs(out_dir, exist_ok=True)
    
    pcap_path = os.path.join(out_dir, pcap_filename)
    json_filename = pcap_filename.replace('.pcap', '_labels.json')
    json_path = os.path.join(out_dir, json_filename)
    
    print(f"Writing {len(packets)} packets to {pcap_path}...")
    wrpcap(pcap_path, packets)
    
    print(f"Writing labels to {json_path}...")
    with open(json_path, 'w') as f:
        json.dump(labels, f, indent=4)
        
    print("Done.")

def get_base_labels(attack_type, description):
    return {
        "attack_type": attack_type,
        "description": description,
        "timestamp": time.time(),
        "flows": []
    }
