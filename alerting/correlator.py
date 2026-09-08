from collections import deque, defaultdict
from alerting.schema import AlertRecord

class AlertCorrelator:
    def __init__(self, time_window_seconds=300):
        self.time_window_seconds = time_window_seconds
        # Index: IP -> deque of (timestamp, alert_id)
        self.ip_to_alerts = defaultdict(deque)
        # Global tracker: deque of (timestamp, alert_id, src_ip, dst_ip)
        self.recent_alerts = deque()
        
    def process(self, new_alert: AlertRecord) -> AlertRecord:
        """
        Correlates the new alert with recent alerts based on IP addresses within the time window.
        O(1) indexed lookup per alert instead of O(N^2) linear scan.
        """
        current_time = new_alert.timestamp
        cutoff = current_time - self.time_window_seconds
        
        # Evict old alerts from the global deque and hash index
        while self.recent_alerts and self.recent_alerts[0][0] < cutoff:
            _, _, old_src, old_dst = self.recent_alerts.popleft()
            if old_src and old_src in self.ip_to_alerts:
                while self.ip_to_alerts[old_src] and self.ip_to_alerts[old_src][0][0] < cutoff:
                    self.ip_to_alerts[old_src].popleft()
                if not self.ip_to_alerts[old_src]:
                    del self.ip_to_alerts[old_src]
            if old_dst and old_dst in self.ip_to_alerts:
                while self.ip_to_alerts[old_dst] and self.ip_to_alerts[old_dst][0][0] < cutoff:
                    self.ip_to_alerts[old_dst].popleft()
                if not self.ip_to_alerts[old_dst]:
                    del self.ip_to_alerts[old_dst]
                    
        related_ids = set()
        new_src = new_alert.flow_id.src_ip if new_alert.flow_id else None
        new_dst = new_alert.flow_id.dst_ip if new_alert.flow_id else None
        
        # Fast indexed lookup for matching past alerts
        if new_src and new_src in self.ip_to_alerts:
            for ts, past_id in self.ip_to_alerts[new_src]:
                if ts >= cutoff:
                    related_ids.add(past_id)
                    
        if new_dst and new_dst in self.ip_to_alerts:
            for ts, past_id in self.ip_to_alerts[new_dst]:
                if ts >= cutoff:
                    related_ids.add(past_id)
                    
        # Cap related IDs to avoid unbounded growth
        capped = list(related_ids)[-20:] if len(related_ids) > 20 else list(related_ids)
        new_alert.related_alert_ids.extend(capped)
        
        # Add new alert to hash index and window
        aid = new_alert.alert_id
        if new_src:
            self.ip_to_alerts[new_src].append((current_time, aid))
        if new_dst:
            self.ip_to_alerts[new_dst].append((current_time, aid))
        self.recent_alerts.append((current_time, aid, new_src, new_dst))
        
        return new_alert
