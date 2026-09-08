import os
import pandas as pd
import joblib
from sklearn.svm import OneClassSVM
from sklearn.metrics import classification_report, confusion_matrix
import warnings

warnings.filterwarnings("ignore")

def train_beaconing_model():
    data_path = os.path.join(os.path.dirname(__file__), 'training_data.csv')
    df = pd.read_csv(data_path)
    
    # Fill NAs
    df['beacon_iat_cv'] = df['beacon_iat_cv'].fillna(1.0)
    df['beacon_mean_iat'] = df['beacon_mean_iat'].fillna(0.0)
    
    # Train One-Class SVM on BENIGN data only
    benign_df = df[df['attack_type'] == 'Benign']
    
    features = ['beacon_iat_cv', 'beacon_mean_iat']
    X_train = benign_df[features]
    
    # Needs to match column names expected by detector
    X_train = X_train.rename(columns={'beacon_iat_cv': 'iat_cv', 'beacon_mean_iat': 'mean_iat'})
    
    # Train
    model = OneClassSVM(nu=0.05, kernel="rbf", gamma="auto")
    if not X_train.empty:
        model.fit(X_train)
    else:
        print("No benign data to train OneClassSVM.")
        return
    
    # Test on held-out split (which includes Benign + Beaconing)
    df_eval = df[df['attack_type'].isin(['Benign', 'Beaconing'])]
    split_idx = int(len(df_eval) * 0.7)
    eval_test = df_eval.iloc[split_idx:]
    
    X_test = eval_test[features].rename(columns={'beacon_iat_cv': 'iat_cv', 'beacon_mean_iat': 'mean_iat'})
    y_test_true = eval_test['is_attack']
    
    # Model returns 1 for inlier (benign), -1 for outlier (attack)
    preds = model.predict(X_test)
    y_pred = [0 if p == 1 else 1 for p in preds]
    
    report = classification_report(y_test_true, y_pred)
    cm = confusion_matrix(y_test_true, y_pred)
    
    out_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(out_dir, exist_ok=True)
    
    model_path = os.path.join(out_dir, 'beaconing_ocsvm.pkl')
    joblib.dump(model, model_path)
    
    with open(os.path.join(out_dir, 'beaconing_metrics.txt'), 'w') as f:
        f.write("Beaconing One-Class SVM Metrics (Chronological Split)\n")
        f.write("======================================================\n\n")
        f.write(report)
        f.write("\nConfusion Matrix:\n")
        f.write(str(cm))
        
    print(f"Beaconing model trained and saved to {model_path}")

if __name__ == "__main__":
    train_beaconing_model()
