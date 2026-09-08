import os
import pandas as pd
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

def train_recon_model():
    data_path = os.path.join(os.path.dirname(__file__), 'training_data.csv')
    if not os.path.exists(data_path):
        return
        
    df = pd.read_csv(data_path)
    
    # Fill NAs
    df['recon_syn_only_ratio'] = df['recon_syn_only_ratio'].fillna(0.0)
    df['recon_scan_activity_score'] = df['recon_scan_activity_score'].fillna(0.0)
    
    # Train Isolation Forest on BENIGN data
    benign_df = df[df['attack_type'] == 'Benign']
    
    features = ['recon_syn_only_ratio', 'recon_scan_activity_score']
    X_train = benign_df[features].rename(columns={
        'recon_syn_only_ratio': 'syn_only_ratio', 
        'recon_scan_activity_score': 'scan_activity_score'
    })
    
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    if not X_train.empty:
        model.fit(X_train)
    else:
        print("No benign data to train Recon IsolationForest.")
        return
        
    # Test on held-out split (which includes Benign + attacks)
    split_idx = int(len(df) * 0.7)
    eval_test = df.iloc[split_idx:]
    
    X_test = eval_test[features].rename(columns={
        'recon_syn_only_ratio': 'syn_only_ratio', 
        'recon_scan_activity_score': 'scan_activity_score'
    })
    
    # Label is 1 for benign (inlier) and -1 for anomaly (outlier) in ISO Forest
    preds = model.predict(X_test)
    y_pred = [0 if p == 1 else 1 for p in preds]
    
    # True labels
    y_test_true = eval_test['is_attack']
    
    report = classification_report(y_test_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_test_true, y_pred)
    
    out_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(out_dir, exist_ok=True)
    
    model_path = os.path.join(out_dir, 'recon_iso.pkl')
    joblib.dump(model, model_path)
    
    with open(os.path.join(out_dir, 'recon_metrics.txt'), 'w') as f:
        f.write("Recon Scan ISO Forest Metrics (Chronological Split)\n")
        f.write("====================================================\n\n")
        f.write(report)
        f.write("\nConfusion Matrix:\n")
        f.write(str(cm))
        
    print(f"Recon model trained and saved to {model_path}")

if __name__ == "__main__":
    train_recon_model()
