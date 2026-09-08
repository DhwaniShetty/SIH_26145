import os
import pandas as pd
import joblib
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, confusion_matrix

def train_ddos_model():
    data_path = os.path.join(os.path.dirname(__file__), 'training_data.csv')
    df = pd.read_csv(data_path)
    
    # Filter for DDoS vs Benign
    df = df[df['attack_type'].isin(['DDoS', 'Benign'])]
    
    features = ['ddos_syn_synack_ratio', 'ddos_dst_pkt_ewma']
    X = df[features]
    y = df['is_attack']
    
    # Time-based split: train on first 70%, test on last 30%
    # Data is sequentially generated in PCAP
    split_idx = int(len(df) * 0.7)
    X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
    y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]
    
    # Needs to match column names expected by detector
    X_train = X_train.rename(columns={'ddos_syn_synack_ratio': 'syn_synack_ratio', 'ddos_dst_pkt_ewma': 'dst_pkt_ewma'})
    X_test = X_test.rename(columns={'ddos_syn_synack_ratio': 'syn_synack_ratio', 'ddos_dst_pkt_ewma': 'dst_pkt_ewma'})
    
    model = LGBMClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)
    
    preds = model.predict(X_test)
    
    report = classification_report(y_test, preds)
    cm = confusion_matrix(y_test, preds)
    
    out_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(out_dir, exist_ok=True)
    
    model_path = os.path.join(out_dir, 'ddos_lgbm.pkl')
    joblib.dump(model, model_path)
    
    with open(os.path.join(out_dir, 'ddos_metrics.txt'), 'w') as f:
        f.write("DDoS LightGBM Detector Metrics (Chronological Split)\n")
        f.write("====================================================\n\n")
        f.write(report)
        f.write("\nConfusion Matrix:\n")
        f.write(str(cm))
        
    print(f"DDoS model trained and saved to {model_path}")

if __name__ == "__main__":
    train_ddos_model()
