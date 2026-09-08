import os
import joblib
import numpy as np
from models.base_detector import BaseDetector

class ExfiltrationDetector(BaseDetector):
    def __init__(self, model_path=None):
        if model_path and os.path.exists(model_path):
            self.iso_model = joblib.load(model_path)
        else:
            self.iso_model = None

    def predict(self, feature_vector):
        score = 0.0
        explanation = ""
        features_used = {}
        
        out_in_ratio = feature_vector.get("outbound_inbound_ratio", 0.0)
        out_b = feature_vector.get("outbound_bytes_ewma", 0.0)
        in_b = feature_vector.get("inbound_bytes_ewma", 0.0)
        
        features_used = {
            "outbound_inbound_ratio": out_in_ratio,
            "outbound_bytes_ewma": out_b,
            "inbound_bytes_ewma": in_b
        }
        
        # 0. Early exit gatekeeper
        if out_b == 0.0 and in_b == 0.0:
            return 0.0, features_used, ""

        # 1. Deterministic CUSUM-like threshold
        if out_in_ratio > 10.0 and out_b > 5000:
            score = 0.85
            explanation = f"High Exfiltration Risk: Outbound/Inbound byte ratio is {out_in_ratio:.1f}x with high volume."
            return score, features_used, explanation
            
        # 2. Multivariate Isolation Forest anomaly detection
        if self.iso_model:
            X = np.array([list(features_used.values())], dtype=np.float32)
            pred = self.iso_model.predict(X)[0]
            
            if pred == -1:
                score = max(score, 0.75)
                explanation = "Isolation Forest detected multivariate volumetric anomaly (potential exfiltration)."
                
        return score, features_used, explanation
