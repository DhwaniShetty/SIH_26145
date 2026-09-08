from features.online_stats import EWMA

class ExfiltrationFeatureExtractor:
    def __init__(self):
        self.outbound_bytes_ewma = EWMA(alpha=0.1)
        self.inbound_bytes_ewma = EWMA(alpha=0.1)
        
    def update(self, meta, is_outbound=True):
        ip_len = meta.get('ip_len', 0)
        if is_outbound:
            self.outbound_bytes_ewma.update(ip_len)
        else:
            self.inbound_bytes_ewma.update(ip_len)

    def extract(self):
        out_b = self.outbound_bytes_ewma.get()
        in_b = self.inbound_bytes_ewma.get()
        
        # Asymmetric outbound/inbound ratio
        out_in_ratio = out_b / max(1.0, in_b)
        
        return {
            "outbound_bytes_ewma": out_b,
            "inbound_bytes_ewma": in_b,
            "outbound_inbound_ratio": out_in_ratio
        }
