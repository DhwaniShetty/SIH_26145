import os
import joblib
from models.base_detector import BaseDetector

class DDoSDetector(BaseDetector):
    def __init__(self, model_path=None):
        if model_path and os.path.exists(model_path):
            self.model = joblib.load(model_path)
        else:
            self.model = None

    def predict(self, feature_vector):
        score = 0.0
        explanation = ""
        features_used = {}
        
        # We expect feature_vector to be from DDoSFeatureExtractor
        # E.g. syn_synack_ratio, src_ip_entropy, dst_pkt_ewma, dst_byte_ewma
        
        syn_ratio = feature_vector.get("syn_synack_ratio", 0)
        pkt_ewma = feature_vector.get("dst_pkt_ewma", 0)
        
        features_used = {
            "syn_synack_ratio": syn_ratio,
            "dst_pkt_ewma": pkt_ewma
        }
        
        # 1. Fast CUSUM / EWMA triage rule (e.g. syn ratio > 10)
        if syn_ratio > 10.0:
            score = 0.95
            explanation = f"High probability of SYN Flood: SYN to SYN-ACK ratio is {syn_ratio:.1f}x."
            return score, features_used, explanation
            
        # 2. LightGBM / Isolation Forest prediction
        if self.model:
            import pandas as pd
            df = pd.DataFrame([features_used])
            # For Isolation Forest, -1 is anomaly, 1 is normal
            # For LightGBM, predict_proba
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(df)[0]
                score = probs[1] if len(probs) > 1 else probs[0]
                if score > 0.5:
                    explanation = f"LGBM classifier flagged flow with confidence {score:.2f}."
            else:
                pred = self.model.predict(df)[0]
                if pred == -1:
                    score = 0.8
                    explanation = "Isolation Forest detected volumetric anomaly."
                    
        return score, features_used, explanation
