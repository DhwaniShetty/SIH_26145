import time
import logging

from features.ddos_features import DDoSFeatureExtractor
from features.beaconing_features import BeaconingFeatureExtractor
from features.dga_dns_features import DGADNSFeatureExtractor
from features.encrypted_meta_features import EncryptedMetaFeatureExtractor
from features.recon_scan_features import ReconScanFeatureExtractor
from features.exfiltration_features import ExfiltrationFeatureExtractor
from features.dns_exfil_features import DNSExfiltrationFeatures

logger = logging.getLogger(__name__)

class FeatureScheduler:
    """
    A tumbling-window feature aggregator.
    Invokes relevant feature modules and emits structured feature vectors.
    """
    def __init__(self, window_1s=1.0, window_5s=5.0, window_60s=60.0):
        self.window_1s = window_1s
        self.window_5s = window_5s
        self.window_60s = window_60s
        
        self.last_1s = 0
        self.last_5s = 0
        self.last_60s = 0
        
        self.ddos = DDoSFeatureExtractor()
        self.beaconing = BeaconingFeatureExtractor()
        self.dga = DGADNSFeatureExtractor()
        self.encrypted = EncryptedMetaFeatureExtractor()
        self.recon = ReconScanFeatureExtractor()
        self.exfil = ExfiltrationFeatureExtractor()
        self.dns_exfil = DNSExfiltrationFeatures()

    def process_packet(self, meta, current_time, dns_parsed=None, tls_parsed=None):
        """
        Feed packet metadata and parsed layers into the streaming features.
        """
        # DDoS
        self.ddos.update(meta)
        
        # Recon
        self.recon.update(meta)
        
        # Exfiltration
        is_outbound = meta['src_ip'].startswith('10.') or meta['src_ip'].startswith('192.168.')
        self.exfil.update(meta, is_outbound=is_outbound)
        
        # Beaconing
        self.beaconing.update(meta, current_time)
        
        # DNS
        if dns_parsed:
            self.dga.update(dns_parsed)
            
            # dns_exfil wants (parsed_dns, is_new_minute). We will mock is_new_minute based on 60s window
            is_new_minute = (current_time - self.last_60s) >= self.window_60s
            self.dns_exfil.update(dns_parsed, is_new_minute)
            
        # TLS
        if tls_parsed:
            self.encrypted.update(meta, tls_parsed, current_time)
        return self._check_windows(meta, current_time)
        
    def _check_windows(self, meta, current_time):
        fired = {}
        if self.last_1s == 0:
            self.last_1s = current_time
            self.last_5s = current_time
            self.last_60s = current_time
            
        if current_time - self.last_1s >= self.window_1s:
            fired.update(self.emit_1s_window(meta['src_ip'], meta['dst_ip']))
            self.last_1s = current_time
            
        if current_time - self.last_5s >= self.window_5s:
            fired.update(self.emit_5s_window(meta['src_ip'], meta['dst_ip']))
            self.last_5s = current_time
            
        if current_time - self.last_60s >= self.window_60s:
            fired.update(self.emit_60s_window(meta['src_ip'], meta['dst_ip']))
            self.last_60s = current_time
            
        fired.pop("type", None)
        return fired
            
    def emit_1s_window(self, src_ip, dst_ip):
        # DDoS and Recon are highly volatile, emit every 1s
        vec = {
            "type": "1s_rollup",
            "ddos": self.ddos.extract(dst_ip),
            "recon": self.recon.extract(src_ip)
        }
        # print("1s Vector:", vec)
        return vec

    def emit_5s_window(self, src_ip, dst_ip):
        vec = {
            "type": "5s_rollup",
            "dga": self.dga.extract(),
            "encrypted": self.encrypted.extract(),
            "dns_exfil": self.dns_exfil.extract()
        }
        return vec

    def emit_60s_window(self, src_ip, dst_ip):
        # Slower moving signals like beaconing and exfiltration
        vec = {
            "type": "60s_rollup",
            "beaconing": self.beaconing.extract(src_ip, dst_ip),
            "exfil": self.exfil.extract()
        }
        return vec

    def extract_all(self, src_ip, dst_ip):
        """Helper to get current state of all features for testing."""
        return {
            "ddos": self.ddos.extract(dst_ip),
            "recon": self.recon.extract(src_ip),
            "dga": self.dga.extract(),
            "encrypted": self.encrypted.extract(),
            "beaconing": self.beaconing.extract(src_ip, dst_ip),
            "exfil": self.exfil.extract(),
            "dns_exfil": self.dns_exfil.extract()
        }
