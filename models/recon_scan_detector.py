import os
import joblib
from models.base_detector import BaseDetector

class ReconScanDetector(BaseDetector):
    def __init__(self, model_path=None):
        if model_path and os.path.exists(model_path):
            self.iso_model = joblib.load(model_path)
        else:
            self.iso_model = None

    def predict(self, feature_vector):
        score = 0.0
        explanation = ""
        features_used = {}
        
        syn_ratio = feature_vector.get("syn_only_ratio", 0.0)
        scan_activity = feature_vector.get("scan_activity_score", 0.0)
        
        features_used = {
            "syn_only_ratio": syn_ratio,
            "scan_activity_score": scan_activity
        }
        
        # 1. Deterministic rules
        # Very high SYN ratio and significant activity indicates a scan
        if syn_ratio > 0.90 and scan_activity > 50:
            score = 0.9
            explanation = f"Deterministic Rule: High SYN-only ratio ({syn_ratio:.2f}) with volume {scan_activity:.0f}."
            return score, features_used, explanation
            
        # 2. Isolation Forest for baseline anomaly scoring
        if self.iso_model:
            import pandas as pd
            df = pd.DataFrame([features_used])
            pred = self.iso_model.predict(df)[0]
            
            if pred == -1:
                score = max(score, 0.75)
                explanation = "Isolation Forest flagged anomalous scanning cardinality relative to baseline."
                
        return score, features_used, explanation
