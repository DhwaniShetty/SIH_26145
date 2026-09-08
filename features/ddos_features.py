from features.online_stats import CountMinSketch, EWMA

class DDoSFeatureExtractor:
    def __init__(self):
        self.src_ip_entropy_cms = CountMinSketch(width=1024, depth=4)
        self.dst_packet_rates = {} # dst_ip -> EWMA
        self.dst_byte_rates = {} # dst_ip -> EWMA
        self.syn_count = 0
        self.syn_ack_count = 0
        self.amp_req_bytes = 0
        self.amp_res_bytes = 0

    def update(self, meta):
        self.src_ip_entropy_cms.add(meta['src_ip'])
        
        dst = meta['dst_ip']
        if dst not in self.dst_packet_rates:
            self.dst_packet_rates[dst] = EWMA(alpha=0.2)
            self.dst_byte_rates[dst] = EWMA(alpha=0.2)
            
        self.dst_packet_rates[dst].update(1) # Simple representation of rate
        self.dst_byte_rates[dst].update(meta.get('ip_len', 0))

        # SYN vs SYN-ACK
        if meta['protocol'] == 'TCP':
            flags = meta.get('tcp_flags', 0)
            if flags == 2: # SYN
                self.syn_count += 1
            elif flags == 18: # SYN-ACK
                self.syn_ack_count += 1
                
        # Amplification proxy (e.g. DNS UDP 53)
        if meta['protocol'] == 'UDP':
            if meta['dst_port'] == 53:
                self.amp_req_bytes += meta.get('ip_len', 0)
            elif meta['src_port'] == 53:
                self.amp_res_bytes += meta.get('ip_len', 0)

    def extract(self, dst_ip):
        syn_ratio = self.syn_count / max(1, self.syn_ack_count)
        amp_ratio = self.amp_res_bytes / max(1, self.amp_req_bytes)
        
        return {
            "src_ip_entropy": self.src_ip_entropy_cms.approximate_entropy(),
            "dst_pkt_ewma": self.dst_packet_rates.get(dst_ip, EWMA()).get(),
            "dst_byte_ewma": self.dst_byte_rates.get(dst_ip, EWMA()).get(),
            "syn_synack_ratio": syn_ratio,
            "amp_byte_ratio": amp_ratio
        }
