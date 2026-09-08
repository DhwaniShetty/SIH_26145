from collections import deque
from alerting.schema import AlertRecord

class AlertCorrelator:
    def __init__(self, time_window_seconds=300):
        self.time_window_seconds = time_window_seconds
        # Deque of AlertRecords
        self.recent_alerts = deque()
        
    def process(self, new_alert: AlertRecord) -> AlertRecord:
        """
        Correlates the new alert with recent alerts based on IP addresses within the time window.
        Mutates the new_alert by appending to related_alert_ids.
        """
        # Evict old alerts
        current_time = new_alert.timestamp
        while self.recent_alerts and (current_time - self.recent_alerts[0].timestamp > self.time_window_seconds):
            self.recent_alerts.popleft()
            
        related_ids = set()
        
        # Link logic: same src_ip or dst_ip indicates relation across different threats
        for past_alert in self.recent_alerts:
            # We skip correlating with self or same detector to avoid noisy self-links
            # (though correlating repeated DGA might be useful, we focus on cross-detector)
            
            # if past_alert.detector == new_alert.detector:
            #     continue
                
            past_src = past_alert.flow_id.src_ip
            past_dst = past_alert.flow_id.dst_ip
            new_src = new_alert.flow_id.src_ip
            new_dst = new_alert.flow_id.dst_ip
            
            # Checking for any overlap in IP addresses
            if (past_src and past_src in (new_src, new_dst)) or \
               (past_dst and past_dst in (new_src, new_dst)):
                related_ids.add(past_alert.alert_id)
                # We can optionally back-link past_alert to new_alert, 
                # but append-only stores usually just append the new record 
                # with links to the past.
                
        new_alert.related_alert_ids.extend(list(related_ids))
        
        # Add to window
        self.recent_alerts.append(new_alert)
        
        return new_alert
