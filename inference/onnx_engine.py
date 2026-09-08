"""
inference/onnx_engine.py

High-performance, in-process ONNX inference engine.
Loads compiled ONNX models and runs vectorized C++ batch scoring via onnxruntime,
eliminating Python GIL contention and per-prediction overhead.
Supports on-demand lazy loading and automatic detector aliasing.
"""

import os
import threading
import numpy as np
import onnxruntime as ort
import logging

logger = logging.getLogger("onnx_engine")
# Suppress onnxruntime shape warning logs
ort.set_default_logger_severity(3)

class SessionCache(dict):
    """Transparent dict-like proxy that lazy-loads ONNX sessions on access."""
    def __init__(self, engine):
        super().__init__()
        self._engine = engine

    def __getitem__(self, key):
        sess = self._engine.get_session(key)
        if sess is None:
            raise KeyError(key)
        return sess

    def __contains__(self, key):
        return key in self._engine

    def get(self, key, default=None):
        sess = self._engine.get_session(key)
        return sess if sess is not None else default

    def keys(self):
        return [k for k in self._engine.MODEL_MAP.keys() if k in self._engine]


class ONNXInferenceEngine:
    MODEL_MAP = {
        "ddos": "ddos_lgbm",
        "beaconing": "beaconing_ocsvm",
        "dga": "dga_gbt",
        "encrypted": "encrypted_rf",
        "recon": "recon_iso",
        "exfil": "exfil_iso",
        "ddos_lgbm": "ddos_lgbm",
        "beaconing_ocsvm": "beaconing_ocsvm",
        "dga_gbt": "dga_gbt",
        "encrypted_rf": "encrypted_rf",
        "recon_iso": "recon_iso",
        "exfil_iso": "exfil_iso"
    }

    def __init__(self, onnx_dir: str):
        self.onnx_dir = onnx_dir
        self._loaded_sessions = {}
        self._lock = threading.Lock()
        self.sessions = SessionCache(self)

    def __contains__(self, name: str) -> bool:
        canonical = self.MODEL_MAP.get(name, name)
        return os.path.exists(os.path.join(self.onnx_dir, f"{canonical}.onnx"))

    def get_session(self, name: str):
        canonical = self.MODEL_MAP.get(name, name)
        with self._lock:
            if canonical in self._loaded_sessions:
                return self._loaded_sessions[canonical]

            path = os.path.join(self.onnx_dir, f"{canonical}.onnx")
            if not os.path.exists(path):
                return None

            try:
                opts = ort.SessionOptions()
                opts.intra_op_num_threads = 1
                opts.inter_op_num_threads = 1
                sess = ort.InferenceSession(path, sess_options=opts, providers=['CPUExecutionProvider'])
                self._loaded_sessions[canonical] = sess
                alias = canonical.split('_')[0]
                self._loaded_sessions[alias] = sess
                logger.info(f"Loaded ONNX model: {canonical} (alias: {alias})")
                return sess
            except Exception as e:
                logger.error(f"Failed to load ONNX model {canonical}: {e}")
                return None

    def predict_ddos(self, syn_ratio: float, pkt_ewma: float) -> float:
        """Run vectorized LightGBM DDoS inference."""
        sess = self.get_session("ddos_lgbm")
        if not sess:
            return 0.0
        X = np.array([[syn_ratio, pkt_ewma]], dtype=np.float32)
        res = sess.run(None, {"float_input": X})
        probs = res[1]
        if probs and isinstance(probs[0], dict):
            return float(probs[0].get(1, 0.0))
        return 0.0

    def predict_beaconing(self, cv: float, mean_iat: float):
        """Run One-Class SVM beaconing inference."""
        sess = self.get_session("beaconing_ocsvm")
        if not sess:
            return 1, 0.0
        X = np.array([[cv, mean_iat]], dtype=np.float32)
        res = sess.run(None, {"float_input": X})
        label = int(res[0][0][0]) if res[0].ndim > 1 else int(res[0][0])
        score = float(res[1][0][0]) if res[1].ndim > 1 else float(res[1][0])
        return label, score

    def predict_dga_gbt(self, avg_len: float, avg_ent: float, nxdomain: float) -> float:
        """Run LightGBM DGA GBT inference."""
        sess = self.get_session("dga_gbt")
        if not sess:
            return 0.0
        X = np.array([[avg_len, avg_ent, nxdomain]], dtype=np.float32)
        res = sess.run(None, {"float_input": X})
        probs = res[1]
        if probs and isinstance(probs[0], dict):
            return float(probs[0].get(1, 0.0))
        return 0.0

    def predict_encrypted_rf(self, mean_sz: float, var_sz: float, mean_ipt: float, sni_len: float) -> float:
        """Run Random Forest encrypted traffic inference."""
        sess = self.get_session("encrypted_rf")
        if not sess:
            return 0.0
        X = np.array([[mean_sz, var_sz, mean_ipt, sni_len]], dtype=np.float32)
        res = sess.run(None, {"float_input": X})
        probs = res[1]
        if probs and isinstance(probs[0], dict):
            return float(probs[0].get(1, 0.0))
        return 0.0

    def predict_recon_iso(self, syn_ratio: float, scan_activity: float) -> int:
        """Run Isolation Forest recon scan inference."""
        sess = self.get_session("recon_iso")
        if not sess:
            return 1
        X = np.array([[syn_ratio, scan_activity]], dtype=np.float32)
        res = sess.run(None, {"float_input": X})
        label = int(res[0][0][0]) if res[0].ndim > 1 else int(res[0][0])
        return label

    def predict_exfil_iso(self, out_in_ratio: float, out_bytes: float, in_bytes: float) -> int:
        """Run Isolation Forest exfiltration inference."""
        sess = self.get_session("exfil_iso")
        if not sess:
            return 1
        X = np.array([[out_in_ratio, out_bytes, in_bytes]], dtype=np.float32)
        res = sess.run(None, {"float_input": X})
        label = int(res[0][0][0]) if res[0].ndim > 1 else int(res[0][0])
        return label
