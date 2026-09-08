import math

class DNSExfiltrationFeatures:
    """
    Extracts features designed to catch DNS Tunneling / Exfiltration.
    Focuses on TXT and CNAME records, tracking the average query length, 
    average entropy, and query rate per minute.
    """
    def __init__(self):
        self.txt_cname_queries_1m = 0
        self.total_query_len_1m = 0
        self.total_entropy_1m = 0.0
        
    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum([p * math.log(p, 2) for p in prob])
        
    def update(self, parsed_dns: dict, is_new_minute: bool):
        if is_new_minute:
            self.txt_cname_queries_1m = 0
            self.total_query_len_1m = 0
            self.total_entropy_1m = 0.0
            
        if not parsed_dns:
            return
            
        for q in parsed_dns.get('queries', []):
            qtype = q.get('type')
            # 16 = TXT, 5 = CNAME (or checking string representations)
            if qtype in [16, 5, 'TXT', 'CNAME']:
                qname = q.get('name', '')
                self.txt_cname_queries_1m += 1
                self.total_query_len_1m += len(qname)
                self.total_entropy_1m += self._shannon_entropy(qname)
                
    def extract(self) -> dict:
        avg_len = 0
        avg_ent = 0.0
        if self.txt_cname_queries_1m > 0:
            avg_len = self.total_query_len_1m / self.txt_cname_queries_1m
            avg_ent = self.total_entropy_1m / self.txt_cname_queries_1m
            
        return {
            "txt_cname_rate": self.txt_cname_queries_1m,
            "txt_cname_avg_len": avg_len,
            "txt_cname_avg_entropy": avg_ent
        }
