import os
import joblib
import numpy as np
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
        amp_ratio = feature_vector.get("amp_byte_ratio", 0)
        entropy = feature_vector.get("src_ip_entropy", 0)
        byte_ewma = feature_vector.get("dst_byte_ewma", 0)
        
        features_used = {
            "syn_synack_ratio": syn_ratio,
            "dst_pkt_ewma": pkt_ewma,
            "amp_byte_ratio": amp_ratio,
            "src_ip_entropy": entropy
        }
        
        # 0. Early exit gatekeeper
        if pkt_ewma < 2.0 and syn_ratio < 2.0 and amp_ratio < 5.0 and entropy < 3.0:
            return 0.0, features_used, ""
            
        # 1. Fast CUSUM / EWMA triage rule for SYN Flood
        if syn_ratio > 10.0:
            score = 0.95
            explanation = f"High probability of SYN Flood: SYN to SYN-ACK ratio is {syn_ratio:.1f}x."
            return score, features_used, explanation

        # 2. Fast triage rule for UDP Reflection / Amplification Flood
        if amp_ratio > 10.0:
            score = 0.98
            explanation = f"UDP Reflection/Amplification Flood: Outbound-to-inbound byte amplification ratio is {amp_ratio:.1f}x."
            return score, features_used, explanation

        # 3. Fast triage rule for Spoofed-Source Floods (high entropy)
        if entropy > 3.0 and (pkt_ewma > 5.0 or byte_ewma > 1000.0):
            score = 0.92
            explanation = f"Spoofed IP Volumetric Flood: Source IP entropy is {entropy:.2f} bits."
            return score, features_used, explanation
            
        # 4. LightGBM / Isolation Forest prediction
        if self.model:
            X = np.array([[syn_ratio, pkt_ewma]], dtype=np.float32)
            # For Isolation Forest, -1 is anomaly, 1 is normal
            # For LightGBM, predict_proba
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)[0]
                score = probs[1] if len(probs) > 1 else probs[0]
                if score > 0.5:
                    explanation = f"LGBM classifier flagged flow with confidence {score:.2f}."
            else:
                pred = self.model.predict(X)[0]
                if pred == -1:
                    score = 0.8
                    explanation = "Isolation Forest detected volumetric anomaly."
                    
        return score, features_used, explanation
