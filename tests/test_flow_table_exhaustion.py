import os
import sys
import time

# Add project root to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from assembler.flow_session_tables import FlowAssembler

def test_flow_table_exhaustion():
    MAX_FLOWS = 1000
    assembler = FlowAssembler(max_flows=MAX_FLOWS)
    
    start_time = time.time()
    
    # Simulate 50,000 unique flows
    for i in range(50000):
        # High cardinality spoofed IPs
        src_ip = f"10.{i % 255}.{i % 255}.{i % 255}"
        dst_ip = "192.168.1.100"
        
        meta = {
            "protocol": "TCP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": i % 65535,
            "dst_port": 80,
            "ip_len": 64
        }
        
        assembler.process_packet_meta(meta, current_time=start_time + (i * 0.001))
        
        # Assert memory stays bounded
        assert len(assembler.flows.table) <= MAX_FLOWS, "Flow table exceeded max bounds!"
        
    print(f"test_flow_table_exhaustion passed. Peak memory usage (table size) bounded at {len(assembler.flows.table)}.")
    print(f"Total evicted flows: {assembler.flows.evicted_count}")

if __name__ == "__main__":
    test_flow_table_exhaustion()
