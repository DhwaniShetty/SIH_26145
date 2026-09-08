import os
import joblib
import numpy as np
from alerting.schema import AlertRecord, FlowID, Evidence

class AlertNormalizer:
    def __init__(self):
        self.calibrators = {}
        calibrators_dir = os.path.join(os.path.dirname(__file__), 'calibrators')
        
        # Load calibrators if they exist
        for det in ["ddos", "beaconing", "dga", "encrypted", "recon", "exfil"]:
            path = os.path.join(calibrators_dir, f"{det}_calibrator.pkl")
            if os.path.exists(path):
                self.calibrators[det] = joblib.load(path)
                
    def get_severity(self, confidence: float) -> str:
        if confidence >= 0.9: return "CRITICAL"
        if confidence >= 0.75: return "HIGH"
        if confidence >= 0.5: return "MEDIUM"
        return "LOW"
        
    def normalize(self, detector_name, raw_score, feature_values, explanation, flow_info, timestamp, window_start=None, window_end=None):
        """
        Maps raw output into the AlertRecord schema applying the calibrated score.
        """
        # Apply Isotonic Regression calibrator if available
        confidence = float(raw_score)
        if detector_name in self.calibrators:
            try:
                # Isotonic regression expects a 1D array
                confidence = float(self.calibrators[detector_name].predict([raw_score])[0])
            except:
                pass # fallback to raw score if failed
                
        # Ensure confidence is bounded 0 to 1
        confidence = max(0.0, min(1.0, confidence))
        
        flow_id = FlowID(
            src_ip=flow_info.get('src_ip', ''),
            dst_ip=flow_info.get('dst_ip', ''),
            src_port=flow_info.get('src_port'),
            dst_port=flow_info.get('dst_port'),
            protocol=flow_info.get('protocol', 'UNKNOWN')
        )
        
        evidence = Evidence(
            features=feature_values,
            explanation=explanation,
            window_start=window_start,
            window_end=window_end
        )
        
        return AlertRecord(
            timestamp=float(timestamp),
            detector=detector_name,
            flow_id=flow_id,
            threat_class=detector_name.upper(),
            severity=self.get_severity(confidence),
            confidence_score=confidence,
            evidence=evidence
        )
