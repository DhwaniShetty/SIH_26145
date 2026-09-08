import math
from features.online_stats import EWMA

def _shannon_entropy(string):
    if not string:
        return 0.0
    freqs = {}
    for char in string:
        freqs[char] = freqs.get(char, 0) + 1
    ent = 0.0
    for count in freqs.values():
        p = count / len(string)
        ent -= p * math.log2(p)
    return ent

class DGADNSFeatureExtractor:
    def __init__(self):
        self.nxdomain_ewma = EWMA(alpha=0.1)
        self.query_length_ewma = EWMA(alpha=0.1)
        self.query_entropy_ewma = EWMA(alpha=0.1)
        
    def update(self, dns_parsed):
        if not dns_parsed:
            return
            
        for q in dns_parsed.get("queries", []):
            name = q.get("name", "")
            if name:
                self.query_length_ewma.update(len(name))
                self.query_entropy_ewma.update(_shannon_entropy(name))
                
        # NXDOMAIN is a flag in DNS response headers (RCODE=3)
        # We would need to pass this from dns_parser.py. For now we use a placeholder:
        is_nxdomain = dns_parsed.get("nxdomain", False)
        self.nxdomain_ewma.update(1 if is_nxdomain else 0)

    def extract(self):
        return {
            "avg_query_length": self.query_length_ewma.get(),
            "avg_query_entropy": self.query_entropy_ewma.get(),
            "nxdomain_rate": self.nxdomain_ewma.get()
        }
