import os
import joblib
import numpy as np
from models.base_detector import BaseDetector

class BeaconingDetector(BaseDetector):
    def __init__(self, model_path=None):
        if model_path and os.path.exists(model_path):
            self.model = joblib.load(model_path) # One-Class SVM or DBSCAN model
        else:
            self.model = None

    def predict(self, feature_vector):
        score = 0.0
        explanation = ""
        features_used = {}
        
        cv = feature_vector.get("iat_cv", 1.0)
        mean_iat = feature_vector.get("mean_iat", 0.0)
        fan_in = feature_vector.get("dst_fan_in", 0)
        
        features_used = {
            "iat_cv": cv,
            "mean_iat": mean_iat,
            "dst_fan_in": fan_in
        }
        
        # 0. Early exit gatekeeper
        if mean_iat == 0.0:
            return 0.0, features_used, ""

        # 1. Deterministic filter: Low CV indicates strict periodicity (C2 beacon)
        if mean_iat > 0 and cv < 0.1:
            score = 0.90
            explanation = f"High periodicity detected: IAT CV is extremely low ({cv:.3f}), mean IAT {mean_iat:.2f}s."
            return score, features_used, explanation
            
        # 2. SVM Model
        if self.model:
            # For OneClassSVM, -1 is outlier (anomaly), 1 is inlier (benign)
            # We select only iat_cv and mean_iat for this model
            X = np.array([[cv, mean_iat]], dtype=np.float32)
            pred = self.model.predict(X)[0]
            if pred == -1:
                # We expect normal traffic to have high CV (bursty). Low CV = anomaly.
                if cv < 0.5:
                    score = 0.85
                    explanation = f"One-Class SVM flagged abnormal timing periodicity (CV={cv:.2f})."
                    
        return score, features_used, explanation
