import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingest.pcap_reader import BoundedPcapReader
from parsers.ip_tcp_udp import parse_packet
from assembler.flow_session_tables import FlowAssembler
import queue

def test_pcap_ingest():
    pcap_path = os.path.join(os.path.dirname(__file__), '../data/syn_flood.pcap')
    if not os.path.exists(pcap_path):
        print(f"Skipping PCAP ingest test: {pcap_path} not found.")
        return
        
    reader = BoundedPcapReader(pcap_path, max_buffer_size=10000)
    assembler = FlowAssembler()
    
    reader.start()
    
    count = 0
    flow_count = 0
    
    while True:
        try:
            ts, buf = reader.get_packet()
            if ts is None:
                break
            
            meta = parse_packet(buf)
            if meta:
                assembler.process_packet_meta(meta, current_time=ts)
                
            count += 1
            
        except queue.Empty:
            continue
            
    reader.stop()
    
    num_flows = len(assembler.flows.table)
    print(f"Processed {count} packets from syn_flood.pcap.")
    print(f"Assembled {num_flows} unique flows.")
    
    assert num_flows > 0, f"Expected flows to be parsed, got {num_flows}"
    print("test_pcap_ingest passed.")

if __name__ == "__main__":
    test_pcap_ingest()
