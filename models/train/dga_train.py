import os
import pandas as pd
import joblib
import torch
import torch.nn as nn
import torch.optim as optim
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, confusion_matrix
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from models.dga_classifier import DGALSTM

def train_gbt_model():
    data_path = os.path.join(os.path.dirname(__file__), 'training_data.csv')
    if not os.path.exists(data_path):
        print(f"Data not found: {data_path}")
        return
        
    df = pd.read_csv(data_path)
    
    # Filter for DGA vs Benign
    df = df[df['attack_type'].isin(['DGA', 'Benign'])]
    
    # Fill NAs
    df['dga_avg_query_length'] = df['dga_avg_query_length'].fillna(0.0)
    df['dga_avg_query_entropy'] = df['dga_avg_query_entropy'].fillna(0.0)
    df['dga_nxdomain_rate'] = df['dga_nxdomain_rate'].fillna(0.0)
    
    features = ['dga_avg_query_length', 'dga_avg_query_entropy', 'dga_nxdomain_rate']
    X = df[features]
    y = df['is_attack']
    
    # Time-based split: train on first 70%, test on last 30%
    split_idx = int(len(df) * 0.7)
    X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
    y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]
    
    # Rename to match expected model features
    X_train = X_train.rename(columns={
        'dga_avg_query_length': 'avg_query_length', 
        'dga_avg_query_entropy': 'avg_query_entropy',
        'dga_nxdomain_rate': 'nxdomain_rate'
    })
    X_test = X_test.rename(columns={
        'dga_avg_query_length': 'avg_query_length', 
        'dga_avg_query_entropy': 'avg_query_entropy',
        'dga_nxdomain_rate': 'nxdomain_rate'
    })
    
    model = LGBMClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)
    
    preds = model.predict(X_test)
    
    report = classification_report(y_test, preds)
    cm = confusion_matrix(y_test, preds)
    
    out_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(out_dir, exist_ok=True)
    
    model_path = os.path.join(out_dir, 'dga_gbt.pkl')
    joblib.dump(model, model_path)
    
    with open(os.path.join(out_dir, 'dga_metrics.txt'), 'w') as f:
        f.write("DGA GBT Detector Metrics (Chronological Split)\n")
        f.write("====================================================\n\n")
        f.write(report)
        f.write("\nConfusion Matrix:\n")
        f.write(str(cm))
        
    print(f"DGA GBT model trained and saved to {model_path}")

def train_lstm_model():
    # Generate a small synthetic corpus of Benign and DGA domains
    benign_domains = ["google.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com", 
                      "github.com", "wikipedia.org", "yahoo.com", "reddit.com", "youtube.com"] * 50
    
    def gen_dga():
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        length = random.randint(12, 25)
        tld = random.choice([".com", ".net", ".org", ".info", ".biz"])
        return "".join(random.choices(chars, k=length)) + tld
        
    dga_domains = [gen_dga() for _ in range(500)]
    
    all_domains = benign_domains + dga_domains
    labels = [0] * len(benign_domains) + [1] * len(dga_domains)
    
    # Shuffle for LSTM training (no timestamps on raw corpus)
    combined = list(zip(all_domains, labels))
    random.shuffle(combined)
    
    model = DGALSTM(vocab_size=256, embedding_dim=16, hidden_dim=32)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.01)
    
    # Simple training loop over domains (batch size 1 for simplicity of varying lengths)
    model.train()
    for epoch in range(3):
        total_loss = 0
        for domain, label in combined:
            indices = [ord(c) for c in domain if ord(c) < 256]
            if not indices:
                continue
            x = torch.tensor([indices], dtype=torch.long)
            y = torch.tensor([[label]], dtype=torch.float32)
            
            optimizer.zero_grad()
            out = model(x)
            loss = criterion(out, y)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
        print(f"LSTM Epoch {epoch+1} Loss: {total_loss / len(combined):.4f}")
        
    out_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(out_dir, exist_ok=True)
    lstm_path = os.path.join(out_dir, 'dga_lstm.pt')
    torch.save(model.state_dict(), lstm_path)
    print(f"DGA LSTM model trained and saved to {lstm_path}")

if __name__ == "__main__":
    train_gbt_model()
    train_lstm_model()
