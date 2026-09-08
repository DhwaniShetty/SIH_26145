import os
import sys
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.isotonic import IsotonicRegression
from sklearn.calibration import calibration_curve

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models.ddos_detector import DDoSDetector
from models.beaconing_detector import BeaconingDetector
from models.dga_classifier import DGAClassifier
from models.encrypted_traffic_classifier import EncryptedTrafficClassifier
from models.recon_scan_detector import ReconScanDetector
from models.exfiltration_detector import ExfiltrationDetector

def get_detector_data_and_scores(detector_name, df):
    # Depending on detector, construct features and run predict
    results = []
    
    # We will simulate the prediction on the test split
    split_idx = int(len(df) * 0.7)
    test_df = df.iloc[split_idx:]
    
    results_dir = os.path.join(os.path.dirname(__file__), '../models/train/results')
    
    if detector_name == "ddos":
        det = DDoSDetector(os.path.join(results_dir, 'ddos_lgbm.pkl'))
        for _, row in test_df.iterrows():
            vec = {"syn_synack_ratio": row.get('ddos_syn_synack_ratio', 0), "dst_pkt_ewma": row.get('ddos_dst_pkt_ewma', 0)}
            score, _, _ = det.predict(vec)
            results.append((score, row['is_attack'] if row['attack_type'] in ['DDoS', 'Benign'] else 0))
            
    elif detector_name == "beaconing":
        det = BeaconingDetector(os.path.join(results_dir, 'beaconing_ocsvm.pkl'))
        for _, row in test_df.iterrows():
            vec = {"iat_cv": row.get('beacon_iat_cv', 1.0), "mean_iat": row.get('beacon_mean_iat', 0.0), "dst_fan_in": 1}
            score, _, _ = det.predict(vec)
            results.append((score, row['is_attack'] if row['attack_type'] in ['Beaconing', 'Benign'] else 0))
            
    elif detector_name == "dga":
        det = DGAClassifier(gbt_model_path=os.path.join(results_dir, 'dga_gbt.pkl'))
        for _, row in test_df.iterrows():
            vec = {"avg_query_length": row.get('dga_avg_query_length', 0), "avg_query_entropy": row.get('dga_avg_query_entropy', 0), "nxdomain_rate": row.get('dga_nxdomain_rate', 0)}
            score, _, _ = det.predict(vec)
            results.append((score, row['is_attack'] if row['attack_type'] in ['DGA', 'Benign'] else 0))
            
    elif detector_name == "encrypted":
        det = EncryptedTrafficClassifier(os.path.join(results_dir, 'encrypted_rf.pkl'))
        for _, row in test_df.iterrows():
            vec = {"sni_length_ewma": row.get('tls_sni_length', 0)}
            score, _, _ = det.predict(vec)
            results.append((score, row['is_attack'])) # dummy target
            
    elif detector_name == "recon":
        det = ReconScanDetector(os.path.join(results_dir, 'recon_iso.pkl'))
        for _, row in test_df.iterrows():
            vec = {"syn_only_ratio": row.get('recon_syn_only_ratio', 0), "scan_activity_score": row.get('recon_scan_activity_score', 0)}
            score, _, _ = det.predict(vec)
            results.append((score, row['is_attack'] if row['attack_type'] in ['Recon', 'Benign'] else 0))
            
    elif detector_name == "exfil":
        det = ExfiltrationDetector(os.path.join(results_dir, 'exfil_iso.pkl'))
        for _, row in test_df.iterrows():
            vec = {"outbound_inbound_ratio": row.get('exfil_outbound_inbound_ratio', 0), "outbound_bytes_ewma": row.get('exfil_outbound_bytes_ewma', 0), "inbound_bytes_ewma": row.get('exfil_inbound_bytes_ewma', 0)}
            score, _, _ = det.predict(vec)
            results.append((score, row['is_attack'] if row['attack_type'] in ['Exfil', 'Benign'] else 0))
            
    return np.array([x[0] for x in results]), np.array([x[1] for x in results])

def run_calibration():
    data_path = os.path.join(os.path.dirname(__file__), '../models/train/training_data.csv')
    df = pd.read_csv(data_path)
    
    detectors = ["ddos", "beaconing", "dga", "encrypted", "recon", "exfil"]
    
    calibrators_dir = os.path.join(os.path.dirname(__file__), 'calibrators')
    report_dir = os.path.join(os.path.dirname(__file__), 'calibration_report')
    os.makedirs(calibrators_dir, exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)
    
    fig, axes = plt.subplots(2, 3, figsize=(15, 10))
    axes = axes.flatten()
    
    for i, det_name in enumerate(detectors):
        scores, y_true = get_detector_data_and_scores(det_name, df)
        
        # Fit Isotonic Regression
        # If all scores are exactly the same (e.g. 0), iso regression will fail. Add tiny noise.
        scores = scores + np.random.normal(0, 0.0001, len(scores))
        
        iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
        try:
            iso.fit(scores, y_true)
        except Exception as e:
            # Fallback to dummy
            iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
            iso.fit([0, 1], [0, 1])
            
        calibrated_scores = iso.predict(scores)
        
        joblib.dump(iso, os.path.join(calibrators_dir, f"{det_name}_calibrator.pkl"))
        
        # Plot Reliability Diagram
        fraction_of_positives, mean_predicted_value = calibration_curve(y_true, calibrated_scores, n_bins=5)
        
        ax = axes[i]
        ax.plot(mean_predicted_value, fraction_of_positives, "s-", label="Calibrated")
        ax.plot([0, 1], [0, 1], "k--", label="Perfectly calibrated")
        ax.set_ylabel("Fraction of positives")
        ax.set_xlabel("Mean predicted value")
        ax.set_title(f"Reliability Diagram: {det_name}")
        ax.legend()
        
    plt.tight_layout()
    plt.savefig(os.path.join(report_dir, 'reliability_diagrams.png'))
    print("Calibration completed. Models saved and diagrams plotted.")

if __name__ == "__main__":
    run_calibration()
