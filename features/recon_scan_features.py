from features.online_stats import CountMinSketch

class ReconScanFeatureExtractor:
    def __init__(self):
        self.distinct_ports_cms = CountMinSketch(width=1024, depth=4)
        self.distinct_hosts_cms = CountMinSketch(width=1024, depth=4)
        self.syn_count = 0
        self.total_tcp_count = 0

    def update(self, meta):
        # Tracking cardinality per source
        src_ip = meta['src_ip']
        dst_ip = meta['dst_ip']
        dst_port = meta.get('dst_port', 0)
        
        # In a real streaming environment with millions of IPs, HLL per IP is memory intensive.
        # Here we approximate global scanning volume or use a bounded cache of CMS per source.
        # For simplicity, we track global distinct pairs to demonstrate cardinality limits.
        self.distinct_ports_cms.add(f"{src_ip}:{dst_port}")
        self.distinct_hosts_cms.add(f"{src_ip}:{dst_ip}")
        
        if meta['protocol'] == 'TCP':
            self.total_tcp_count += 1
            if meta.get('tcp_flags', 0) == 2: # SYN
                self.syn_count += 1

    def extract(self, src_ip):
        # The true distinct count requires HLL. CMS gives frequency, so we return 
        # a pseudo-metric for scanning activity (e.g. ratio of SYNs).
        syn_ratio = self.syn_count / max(1, self.total_tcp_count)
        
        return {
            "syn_only_ratio": syn_ratio,
            "scan_activity_score": syn_ratio * self.syn_count
        }
