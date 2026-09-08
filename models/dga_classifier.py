import os
import math
import joblib
import numpy as np
from models.base_detector import BaseDetector

class DGAClassifier(BaseDetector):
    def __init__(self, gbt_model_path=None, lstm_model_path=None):
        self.gbt_model = None
        self.lstm_model = None
        self.lstm_model_path = lstm_model_path
        
        if gbt_model_path and os.path.exists(gbt_model_path):
            self.gbt_model = joblib.load(gbt_model_path)

    def _ensure_lstm_loaded(self):
        """Lazy-loads PyTorch and the character-level LSTM weights only when requested."""
        if self.lstm_model is not None:
            return True
        if not self.lstm_model_path or not os.path.exists(self.lstm_model_path):
            return False

        try:
            import torch
            import torch.nn as nn

            class DGALSTM(nn.Module):
                def __init__(self, vocab_size, embedding_dim, hidden_dim):
                    super(DGALSTM, self).__init__()
                    self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
                    self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True)
                    self.fc = nn.Linear(hidden_dim, 1)
                    self.sigmoid = nn.Sigmoid()

                def forward(self, x):
                    embedded = self.embedding(x)
                    lstm_out, (hidden, cell) = self.lstm(embedded)
                    last_hidden = hidden[-1, :, :]
                    out = self.fc(last_hidden)
                    return self.sigmoid(out)

            model = DGALSTM(vocab_size=256, embedding_dim=16, hidden_dim=32)
            model.load_state_dict(torch.load(self.lstm_model_path, map_location=torch.device('cpu')))
            model.eval()
            self.lstm_model = model
            return True
        except Exception:
            return False

    def predict(self, feature_vector):
        score = 0.0
        explanation = ""
        features_used = {}
        
        avg_len = feature_vector.get("avg_query_length", 0)
        avg_ent = feature_vector.get("avg_query_entropy", 0)
        nxdomain = feature_vector.get("nxdomain_rate", 0)
        
        features_used = {
            "avg_query_length": avg_len,
            "avg_query_entropy": avg_ent,
            "nxdomain_rate": nxdomain
        }
        
        # 0. Early exit gatekeeper
        if avg_len == 0:
            return 0.0, features_used, ""
            
        # 1. Cheap pre-filter heuristic (Entropy + Length)
        if avg_ent > 3.5 and avg_len > 15:
            score = 0.7
            explanation = f"Heuristic Pre-filter: High query entropy ({avg_ent:.2f}) and length ({avg_len:.1f})."
            
            # If the LSTM is available, invoke it for a deeper check
            # Normally we'd pass the raw domain string, but our scheduler currently aggregates.
            # We'll use the GBT model as the main classifier for the aggregated volumetric features.
            
        # 2. GBT on volumetric features (NXDOMAIN, length, entropy)
        if self.gbt_model:
            X = np.array([list(features_used.values())], dtype=np.float32)
            if hasattr(self.gbt_model, "predict_proba"):
                probs = self.gbt_model.predict_proba(X)[0]
                gbt_score = probs[1] if len(probs) > 1 else probs[0]
                
                if gbt_score > 0.5:
                    score = max(score, gbt_score)
                    explanation = f"GBT flagged tunneling/DGA behavior (prob: {gbt_score:.2f}). " + explanation
                    
        return score, features_used, explanation
        
    def predict_domain_string(self, domain_str):
        """
        Directly predict on a single domain string using the LSTM.
        """
        if not self._ensure_lstm_loaded():
            return 0.0, "LSTM not loaded"

        import torch
        # Convert string to tensor
        indices = [ord(c) for c in domain_str if ord(c) < 256]
        if not indices:
            return 0.0, "Empty domain"
            
        tensor = torch.tensor([indices], dtype=torch.long)
        
        with torch.no_grad():
            prob = self.lstm_model(tensor).item()
            
        return prob, f"LSTM DGA probability: {prob:.2f}"
