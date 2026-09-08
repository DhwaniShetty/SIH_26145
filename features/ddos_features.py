from features.online_stats import CountMinSketch, EWMA

class DDoSFeatureExtractor:
    def __init__(self):
        self.src_ip_entropy_cms = CountMinSketch(width=1024, depth=4)
        self.dst_state = {} # dst_ip -> {'pkt_ewma': EWMA, 'byte_ewma': EWMA, 'last_time': float}
        self.syn_count = 0
        self.syn_ack_count = 0
        self.amp_req_bytes = 0
        self.amp_res_bytes = 0

    def update(self, meta, current_time):
        self.src_ip_entropy_cms.add(meta['src_ip'])
        
        dst = meta['dst_ip']
        if dst not in self.dst_state:
            self.dst_state[dst] = {
                'pkt_ewma': EWMA(alpha=0.2),
                'byte_ewma': EWMA(alpha=0.2),
                'last_time': current_time
            }
        else:
            self.dst_state[dst]['last_time'] = current_time
            
        pkts = meta.get('orig_pkts', 1)
        self.dst_state[dst]['pkt_ewma'].update(pkts)
        self.dst_state[dst]['byte_ewma'].update(meta.get('ip_len', 0))

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
        
        state = self.dst_state.get(dst_ip)
        pkt_rate = state['pkt_ewma'].get() if state else 0.0
        byte_rate = state['byte_ewma'].get() if state else 0.0
        
        return {
            "src_ip_entropy": self.src_ip_entropy_cms.approximate_entropy(),
            "dst_pkt_ewma": pkt_rate,
            "dst_byte_ewma": byte_rate,
            "syn_synack_ratio": syn_ratio,
            "amp_byte_ratio": amp_ratio
        }

    def sweep_stale_state(self, current_time, ttl=60.0):
        stale_dsts = [dst for dst, data in self.dst_state.items() if (current_time - data['last_time']) > ttl]
        for dst in stale_dsts:
            del self.dst_state[dst]
