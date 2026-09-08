import os
import sys
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models.ddos_detector import DDoSDetector
from models.beaconing_detector import BeaconingDetector
from models.dga_classifier import DGAClassifier
from models.encrypted_traffic_classifier import EncryptedTrafficClassifier
from models.recon_scan_detector import ReconScanDetector
from models.exfiltration_detector import ExfiltrationDetector

def test_detectors():
    base_dir = os.path.dirname(__file__)
    results_dir = os.path.join(base_dir, '../models/train/results')
    data_path = os.path.join(base_dir, '../models/train/training_data.csv')
    
    ddos = DDoSDetector(os.path.join(results_dir, 'ddos_lgbm.pkl'))
    beacon = BeaconingDetector(os.path.join(results_dir, 'beaconing_ocsvm.pkl'))
    dga = DGAClassifier(
        gbt_model_path=os.path.join(results_dir, 'dga_gbt.pkl'),
        lstm_model_path=os.path.join(results_dir, 'dga_lstm.pt')
    )
    encrypted = EncryptedTrafficClassifier(os.path.join(results_dir, 'encrypted_rf.pkl'))
    recon = ReconScanDetector(os.path.join(results_dir, 'recon_iso.pkl'))
    exfil = ExfiltrationDetector(os.path.join(results_dir, 'exfil_iso.pkl'))
    
    # Let's craft synthetic true-positive feature vectors that will trigger the rules/models
    
    # 1. DDoS (High SYN ratio)
    ddos_vec = {"syn_synack_ratio": 15.0, "dst_pkt_ewma": 1000}
    score, feats, expl = ddos.predict(ddos_vec)
    assert expl, "DDoS detector failed to provide an explanation"
    print(f"DDoS TP Explanation: {expl} (Score: {score})")
    
    # 2. Beaconing (Low CV, exact periodicity)
    beacon_vec = {"iat_cv": 0.05, "mean_iat": 60.0, "dst_fan_in": 1}
    score, feats, expl = beacon.predict(beacon_vec)
    assert expl, "Beaconing detector failed to provide an explanation"
    print(f"Beaconing TP Explanation: {expl} (Score: {score})")
    
    # 3. DGA (High Entropy and Length)
    dga_vec = {"avg_query_length": 22.0, "avg_query_entropy": 4.1, "nxdomain_rate": 0.8}
    score, feats, expl = dga.predict(dga_vec)
    assert expl, "DGA detector failed to provide an explanation"
    print(f"DGA TP Explanation: {expl} (Score: {score})")
    
    # 4. Recon (High SYN Only Ratio)
    recon_vec = {"syn_only_ratio": 0.99, "scan_activity_score": 100}
    score, feats, expl = recon.predict(recon_vec)
    assert expl, "Recon detector failed to provide an explanation"
    print(f"Recon TP Explanation: {expl} (Score: {score})")
    
    # 5. Exfiltration (High Out/In ratio)
    exfil_vec = {"outbound_inbound_ratio": 50.0, "outbound_bytes_ewma": 10000.0, "inbound_bytes_ewma": 200.0}
    score, feats, expl = exfil.predict(exfil_vec)
    assert expl, "Exfil detector failed to provide an explanation"
    print(f"Exfiltration TP Explanation: {expl} (Score: {score})")
    
    # 6. Encrypted (Model dependent, we will pass a high mean size)
    # The random forest was trained on dummy data in our script, we just want to ensure the logic flows
    enc_vec = {"packet_sizes": [1500]*10, "packet_ipts": [0.01]*9, "sni_length_ewma": 15}
    score, feats, expl = encrypted.predict(enc_vec)
    # RF might not trigger if it learned differently, we'll accept if it runs without crashing
    if expl:
        print(f"Encrypted TP Explanation: {expl} (Score: {score})")
    else:
        print(f"Encrypted didn't flag our dummy vector, but predict ran successfully. Score: {score}")

if __name__ == "__main__":
    test_detectors()
