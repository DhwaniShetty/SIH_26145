"""
inference/export_onnx.py

Robust script to export all trained models into standard ONNX format.
Supported models:
  - ddos_lgbm (LightGBM)
  - beaconing_ocsvm (OneClassSVM)
  - dga_gbt (LightGBM)
  - encrypted_rf (RandomForest)
  - recon_iso (IsolationForest)
  - exfil_iso (IsolationForest)
  - dga_lstm (PyTorch LSTM)
"""

import os
import sys
import logging
import warnings
import joblib

warnings.simplefilter("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("export_onnx")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(ROOT_DIR, "models", "train", "results")
ONNX_DIR = os.path.join(ROOT_DIR, "models", "train", "onnx")
os.makedirs(ONNX_DIR, exist_ok=True)

def export_all():
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType as LGBMFloatTensorType
    import torch
    import torch.nn as nn

    results = {}

    # 1. LightGBM models: ddos_lgbm (2 features), dga_gbt (3 features)
    lgbm_models = {
        "ddos_lgbm": 2,
        "dga_gbt": 3
    }
    for name, n_f in lgbm_models.items():
        pkl_path = os.path.join(RESULTS_DIR, f"{name}.pkl")
        out_path = os.path.join(ONNX_DIR, f"{name}.onnx")
        if os.path.exists(pkl_path):
            try:
                m = joblib.load(pkl_path)
                initial_types = [("float_input", LGBMFloatTensorType([None, n_f]))]
                onnx_m = convert_lightgbm(m, initial_types=initial_types, target_opset=15)
                with open(out_path, "wb") as f:
                    f.write(onnx_m.SerializeToString())
                results[name] = True
                logger.info(f"[OK] Exported {name} -> {out_path}")
            except Exception as e:
                results[name] = False
                logger.error(f"[FAIL] {name}: {e}")

    # 2. Sklearn standard models: beaconing_ocsvm (2 features), encrypted_rf (4 features)
    sklearn_models = {
        "beaconing_ocsvm": 2,
        "encrypted_rf": 4
    }
    for name, n_f in sklearn_models.items():
        pkl_path = os.path.join(RESULTS_DIR, f"{name}.pkl")
        out_path = os.path.join(ONNX_DIR, f"{name}.onnx")
        if os.path.exists(pkl_path):
            try:
                m = joblib.load(pkl_path)
                initial_types = [("float_input", FloatTensorType([None, n_f]))]
                onnx_m = convert_sklearn(m, initial_types=initial_types, target_opset={"ai.onnx.ml": 3, "": 15})
                with open(out_path, "wb") as f:
                    f.write(onnx_m.SerializeToString())
                results[name] = True
                logger.info(f"[OK] Exported {name} -> {out_path}")
            except Exception as e:
                results[name] = False
                logger.error(f"[FAIL] {name}: {e}")

    # 3. Isolation Forest models: recon_iso (2 features), exfil_iso (3 features)
    iso_models = {
        "recon_iso": 2,
        "exfil_iso": 3
    }
    for name, n_f in iso_models.items():
        pkl_path = os.path.join(RESULTS_DIR, f"{name}.pkl")
        out_path = os.path.join(ONNX_DIR, f"{name}.onnx")
        if os.path.exists(pkl_path):
            try:
                m = joblib.load(pkl_path)
                initial_types = [("float_input", FloatTensorType([None, n_f]))]
                onnx_m = convert_sklearn(m, initial_types=initial_types, target_opset={" ": 15, "ai.onnx.ml": 3} if False else {"": 15, "ai.onnx.ml": 3})
                with open(out_path, "wb") as f:
                    f.write(onnx_m.SerializeToString())
                results[name] = True
                logger.info(f"[OK] Exported {name} -> {out_path}")
            except Exception as e:
                results[name] = False
                logger.error(f"[FAIL] {name}: {e}")

    # 4. PyTorch DGA LSTM
    pt_path = os.path.join(RESULTS_DIR, "dga_lstm.pt")
    out_path = os.path.join(ONNX_DIR, "dga_lstm.onnx")
    if os.path.exists(pt_path):
        try:
            class DGALSTM(nn.Module):
                def __init__(self, vocab_size=256, embedding_dim=16, hidden_dim=32):
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

            model = DGALSTM()
            model.load_state_dict(torch.load(pt_path, map_location="cpu", weights_only=True))
            model.eval()

            dummy_input = torch.randint(0, 255, (1, 32), dtype=torch.long)
            torch.onnx.export(
                model,
                dummy_input,
                out_path,
                opset_version=18,
                input_names=["input"],
                output_names=["output"],
                dynamo=False,
                dynamic_axes={"input": {0: "batch_size", 1: "seq_len"}, "output": {0: "batch_size"}}
            )
            results["dga_lstm"] = True
            logger.info(f"[OK] Exported dga_lstm -> {out_path}")
        except Exception as e:
            results["dga_lstm"] = False
            logger.error(f"[FAIL] dga_lstm: {e}")

    logger.info("=== ONNX Export Complete ===")
    for k, v in results.items():
        logger.info(f"  {'✓' if v else '✗'} {k}")

if __name__ == "__main__":
    export_all()
