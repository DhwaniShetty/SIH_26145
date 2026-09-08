from features.online_stats import EWMA

class EncryptedMetaFeatureExtractor:
    def __init__(self, max_packet_history=10):
        self.packet_sizes = []
        self.packet_timings = []
        self.max_packet_history = max_packet_history
        self.sni_entropy_ewma = EWMA(alpha=0.2)
        
    def update(self, meta, tls_parsed, current_time):
        # Sequence of packet sizes (structurally dropping content)
        if len(self.packet_sizes) < self.max_packet_history:
            self.packet_sizes.append(meta.get('ip_len', 0))
            self.packet_timings.append(current_time)
            
        # Extract metadata from TLS parser
        if tls_parsed:
            sni = tls_parsed.get("sni")
            if sni:
                # Basic string length proxy for entropy/variance
                self.sni_entropy_ewma.update(len(sni))

    def extract(self):
        # Compute inter-packet timings
        ipts = []
        for i in range(1, len(self.packet_timings)):
            ipts.append(self.packet_timings[i] - self.packet_timings[i-1])
            
        return {
            "packet_sizes": self.packet_sizes,
            "packet_ipts": ipts,
            "sni_length_ewma": self.sni_entropy_ewma.get()
        }
