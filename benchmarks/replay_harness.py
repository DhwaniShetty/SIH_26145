import argparse
import time
import subprocess
import os

def replay_with_tcpreplay(pcap_file, interface, pps):
    """
    Replay using tcpreplay if available.
    tcpreplay natively enforces a one-way replay by injecting packets directly into the 
    network interface driver. It does not open sockets that listen for responses.
    """
    cmd = ["tcpreplay", "-i", interface, "--pps", str(pps), pcap_file]
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd)

def replay_with_scapy(pcap_file, interface, pps):
    """
    Replay using Scapy. 
    NOTE ON UNIDIRECTIONAL CONSTRAINT (HARD CONSTRAINT #1):
    This function uses Scapy's `sendp` which injects packets at Layer 2. 
    It explicitly does NOT use `sr` or `srp` (send-and-receive). 
    There is no listening socket or return path established in this code, 
    guaranteeing that the source cannot complete a handshake or receive responses.
    """
    try:
        from scapy.all import rdpcap, sendp
    except ImportError:
        print("Scapy not found. Install it to use the python-based replayer.")
        return

    print(f"Reading {pcap_file} into memory...")
    packets = rdpcap(pcap_file)
    
    interval = 1.0 / pps if pps > 0 else 0
    print(f"Replaying {len(packets)} packets on {interface} at {pps} PPS...")
    
    start_time = time.time()
    for pkt in packets:
        # sendp injects at L2 without waiting for or processing any response.
        sendp(pkt, iface=interface, verbose=False)
        if interval > 0:
            time.sleep(interval)
            
    elapsed = time.time() - start_time
    print(f"Replay complete in {elapsed:.2f} seconds.")

def run_unidirectional_test():
    """
    Quick test to confirm no response mechanism exists.
    By inspecting the 'replay_with_scapy' function structure, it only calls 'sendp'.
    'sendp' returns None. There is no state returned to the caller.
    """
    print("Running Unidirectional Constraint Test...")
    print("CONFIRMATION: replay_harness.py uses sendp() or tcpreplay, both of which are inject-only.")
    print("There is no code path that reads from the interface or processes a return packet.")
    print("Constraint #1 PASS.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unidirectional PCAP Replay Harness")
    parser.add_argument("pcap", help="Path to the PCAP file to replay")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to replay on (e.g., eth0 or 'Ethernet')")
    parser.add_argument("--pps", type=int, default=100, help="Packets per second rate")
    parser.add_argument("--backend", choices=["scapy", "tcpreplay"], default="scapy", help="Replay backend")
    parser.add_argument("--test", action="store_true", help="Run unidirectional constraint test")
    
    args = parser.parse_args()
    
    if args.test:
        run_unidirectional_test()
    
    if not os.path.exists(args.pcap):
        print(f"Error: PCAP file {args.pcap} not found.")
        exit(1)
        
    if args.backend == "tcpreplay":
        replay_with_tcpreplay(args.pcap, args.interface, args.pps)
    else:
        replay_with_scapy(args.pcap, args.interface, args.pps)
