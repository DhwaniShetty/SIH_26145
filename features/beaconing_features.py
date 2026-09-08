from features.online_stats import Welford, CountMinSketch

class BeaconingFeatureExtractor:
    def __init__(self):
        # pair -> (last_time, Welford_IAT)
        self.flow_iats = {} 
        self.dst_fan_in_cms = CountMinSketch(width=512, depth=3)

    def update(self, meta, current_time):
        src = meta['src_ip']
        dst = meta['dst_ip']
        pair = f"{src}->{dst}"
        
        if pair not in self.flow_iats:
            self.flow_iats[pair] = {
                'last_time': current_time,
                'welford': Welford()
            }
        else:
            last_time = self.flow_iats[pair]['last_time']
            iat = current_time - last_time
            if iat > 0:
                self.flow_iats[pair]['welford'].update(iat)
            self.flow_iats[pair]['last_time'] = current_time
            
        self.dst_fan_in_cms.add(dst)

    def extract(self, src_ip, dst_ip):
        pair = f"{src_ip}->{dst_ip}"
        stat = self.flow_iats.get(pair)
        
        cv = 0.0
        mean_iat = 0.0
        if stat and stat['welford'].count > 1:
            mean_iat = stat['welford'].mean
            stddev = stat['welford'].get_stddev()
            if mean_iat > 0:
                cv = stddev / mean_iat  # Low CV indicates periodic beaconing
                
        fan_in = self.dst_fan_in_cms.get(dst_ip)
        
        return {
            "mean_iat": mean_iat,
            "iat_cv": cv,
            "dst_fan_in": fan_in
        }

    def sweep_stale_state(self, current_time, ttl=120.0):
        stale_pairs = [pair for pair, data in self.flow_iats.items() if (current_time - data['last_time']) > ttl]
        for pair in stale_pairs:
            del self.flow_iats[pair]
