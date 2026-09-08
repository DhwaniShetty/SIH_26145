import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models.beaconing_detector import BeaconingDetector
from models.recon_scan_detector import ReconScanDetector

def test_beaconing_jitter():
    print("\n--- Adversarial Degradation Curve: Beaconing Jitter ---")
    results_dir = os.path.join(os.path.dirname(__file__), '../models/train/results')
    det = BeaconingDetector(os.path.join(results_dir, 'beaconing_ocsvm.pkl'))
    
    # Base feature: rigid beaconing has CV ~ 0.0
    # High jitter evasion increases CV towards 1.0 (approaching Poisson/random)
    
    print(f"{'Jitter Level (CV)':<20} | {'Detector Score (Conf)':<25} | {'Detected?'}")
    print("-" * 65)
    
    for cv in [0.01, 0.1, 0.3, 0.5, 0.7, 0.9, 1.2]:
        f = {"iat_cv": cv, "mean_iat": 10.0, "dst_fan_in": 1}
        score, _, expl = det.predict(f)
        detected = "YES" if score > 0.5 and expl else "NO"
        print(f"{cv:<20.2f} | {score:<25.4f} | {detected}")

def test_recon_slow_low():
    print("\n--- Adversarial Degradation Curve: Slow-and-Low Recon ---")
    results_dir = os.path.join(os.path.dirname(__file__), '../models/train/results')
    det = ReconScanDetector(os.path.join(results_dir, 'recon_iso.pkl'))
    
    # Base feature: high volume scanning (e.g. 500 scans/sec)
    # Slow-and-low evasion lowers this significantly.
    # The feature scan_activity_score correlates to rate/volume.
    
    print(f"{'Scan Volume/Rate':<20} | {'Detector Score (Conf)':<25} | {'Detected?'}")
    print("-" * 65)
    
    for vol in [1000, 500, 100, 50, 20, 10, 5, 1]:
        f = {"syn_only_ratio": 1.0, "scan_activity_score": float(vol)}
        score, _, expl = det.predict(f)
        detected = "YES" if score > 0.5 and expl else "NO"
        print(f"{vol:<20} | {score:<25.4f} | {detected}")

if __name__ == "__main__":
    test_beaconing_jitter()
    test_recon_slow_low()
