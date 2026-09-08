import os
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

def train_exfil_model():
    data_path = os.path.join(os.path.dirname(__file__), 'training_data.csv')
    if not os.path.exists(data_path):
        return
        
    df = pd.read_csv(data_path)
    
    # Fill NAs
    df['exfil_outbound_inbound_ratio'] = df['exfil_outbound_inbound_ratio'].fillna(0.0)
    df['exfil_outbound_bytes_ewma'] = df['exfil_outbound_bytes_ewma'].fillna(0.0)
    df['exfil_inbound_bytes_ewma'] = df['exfil_inbound_bytes_ewma'].fillna(0.0)
    
    # Train Isolation Forest on BENIGN data
    benign_df = df[df['attack_type'] == 'Benign']
    
    features = ['exfil_outbound_inbound_ratio', 'exfil_outbound_bytes_ewma', 'exfil_inbound_bytes_ewma']
    X_train = benign_df[features].rename(columns={
        'exfil_outbound_inbound_ratio': 'outbound_inbound_ratio', 
        'exfil_outbound_bytes_ewma': 'outbound_bytes_ewma',
        'exfil_inbound_bytes_ewma': 'inbound_bytes_ewma'
    })
    
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    if not X_train.empty:
        model.fit(X_train)
    else:
        print("No benign data to train Exfil IsolationForest.")
        return
        
    # Test on held-out split
    split_idx = int(len(df) * 0.7)
    eval_test = df.iloc[split_idx:]
    
    X_test = eval_test[features].rename(columns={
        'exfil_outbound_inbound_ratio': 'outbound_inbound_ratio', 
        'exfil_outbound_bytes_ewma': 'outbound_bytes_ewma',
        'exfil_inbound_bytes_ewma': 'inbound_bytes_ewma'
    })
    
    preds = model.predict(X_test)
    y_pred = [0 if p == 1 else 1 for p in preds]
    
    y_test_true = eval_test['is_attack']
    
    report = classification_report(y_test_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_test_true, y_pred)
    
    out_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(out_dir, exist_ok=True)
    
    model_path = os.path.join(out_dir, 'exfil_iso.pkl')
    joblib.dump(model, model_path)
    
    with open(os.path.join(out_dir, 'exfil_metrics.txt'), 'w') as f:
        f.write("Exfiltration ISO Forest Metrics (Chronological Split)\n")
        f.write("====================================================\n\n")
        f.write(report)
        f.write("\nConfusion Matrix:\n")
        f.write(str(cm))
        
    print(f"Exfiltration model trained and saved to {model_path}")

if __name__ == "__main__":
    train_exfil_model()
