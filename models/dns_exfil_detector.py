import os
import joblib
import numpy as np
from typing import Tuple, Dict, Any

from models.base_detector import BaseDetector

class DNSExfiltrationDetector(BaseDetector):
    """
    Detects DNS Exfiltration / Tunneling based on TXT/CNAME query 
    volume, query length, and entropy.
    Uses an Isolation Forest to flag anomalously high entropy/length.
    """
    def __init__(self, model_path: str = None):
        self.model = None
        self.features = ['txt_cname_rate', 'txt_cname_avg_len', 'txt_cname_avg_entropy']
        if model_path and os.path.exists(model_path):
            self.model = joblib.load(model_path)
            
    def predict(self, feature_vector: Dict[str, Any]) -> Tuple[float, Dict[str, Any], str]:
        if not self.model:
            # Fallback heuristic if no model is trained
            return self._heuristic_predict(feature_vector)
            
        try:
            # 0. Gatekeeper check
            if feature_vector.get('txt_cname_rate', 0.0) == 0.0:
                return 0.0, feature_vector, ""

            vals = [feature_vector.get(k, 0.0) for k in self.features]
            X = np.array([vals], dtype=np.float32)
            score = self.model.decision_function(X)[0]
            # Convert isolation forest score to probability-like [0, 1]
            prob = 1.0 - (1.0 / (1.0 + float(score) + 1.0)) # approx normalization
            
            if prob > 0.6:
                expl = f"DNS Exfiltration detected: Entropy={feature_vector.get('txt_cname_avg_entropy', 0):.2f}, AvgLen={feature_vector.get('txt_cname_avg_len', 0):.1f}"
                return prob, feature_vector, expl
            return prob, feature_vector, ""
        except Exception:
            return self._heuristic_predict(feature_vector)
            
    def _heuristic_predict(self, f: Dict[str, Any]) -> Tuple[float, Dict[str, Any], str]:
        # Simple thresholding
        ent = f.get('txt_cname_avg_entropy', 0.0)
        length = f.get('txt_cname_avg_len', 0.0)
        rate = f.get('txt_cname_rate', 0.0)
        
        if ent > 4.5 and length > 40 and rate > 5:
            return 0.85, f, f"High entropy ({ent:.2f}) and length ({length:.1f}) in {rate} TXT/CNAME queries per min."
        return 0.0, f, ""
