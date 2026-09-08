import os
import joblib
import numpy as np
from models.base_detector import BaseDetector

class EncryptedTrafficClassifier(BaseDetector):
    def __init__(self, model_path=None):
        if model_path and os.path.exists(model_path):
            self.rf_model = joblib.load(model_path)
        else:
            self.rf_model = None
            
        # Placeholder for PyTorch 1D-CNN
        # Note: A deep sequence model (e.g., PyTorch nn.Conv1d) could be substituted here 
        # to directly model the packet-size and inter-packet-timing sequences 
        # if more robust labeled sequence data becomes available.
        # self.cnn_model = DeepEncryptedCNN(...)

    def predict(self, feature_vector):
        score = 0.0
        explanation = ""
        features_used = {}
        
        packet_sizes = feature_vector.get("packet_sizes", [])
        packet_ipts = feature_vector.get("packet_ipts", [])
        sni_len = feature_vector.get("sni_length_ewma", 0)
        
        # Flatten sequence into statistical features for Random Forest
        mean_size = np.mean(packet_sizes) if packet_sizes else 0
        var_size = np.var(packet_sizes) if packet_sizes else 0
        mean_ipt = np.mean(packet_ipts) if packet_ipts else 0
        
        features_used = {
            "mean_size": mean_size,
            "var_size": var_size,
            "mean_ipt": mean_ipt,
            "sni_length_ewma": sni_len
        }
        
        # 0. Early exit gatekeeper
        if not packet_sizes and not packet_ipts and sni_len == 0:
            return 0.0, features_used, ""

        if self.rf_model:
            X = np.array([list(features_used.values())], dtype=np.float32)
            if hasattr(self.rf_model, "predict_proba"):
                probs = self.rf_model.predict_proba(X)[0]
                rf_score = probs[1] if len(probs) > 1 else probs[0]
                
                if rf_score > 0.5:
                    score = rf_score
                    explanation = f"Random Forest detected anomalous TLS handshake sequence (score: {rf_score:.2f})."
                    
        return score, features_used, explanation
