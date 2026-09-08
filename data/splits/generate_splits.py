import json
import os
import random
from datetime import datetime

def generate_chronological_splits(data_records, train_ratio=0.7, val_ratio=0.15):
    """
    Splits data chronologically.
    Assumes data_records is a list of dicts containing a 'timestamp' field.
    """
    # Sort chronologically
    sorted_records = sorted(data_records, key=lambda x: x.get('timestamp', 0))
    
    total = len(sorted_records)
    train_end = int(total * train_ratio)
    val_end = train_end + int(total * val_ratio)
    
    train_split = sorted_records[:train_end]
    val_split = sorted_records[train_end:val_end]
    test_split = sorted_records[val_end:]
    
    return train_split, val_split, test_split

def generate_entity_holdout_splits(data_records, entity_key="src_ip", holdout_ratio=0.2):
    """
    Splits data based on an entity holdout (e.g., holding out specific C2 IPs for testing).
    Useful to ensure the model generalizes to unseen C2s/exfil targets.
    """
    unique_entities = list(set([r.get(entity_key) for r in data_records if r.get(entity_key)]))
    random.shuffle(unique_entities)
    
    holdout_count = max(1, int(len(unique_entities) * holdout_ratio))
    holdout_entities = set(unique_entities[:holdout_count])
    
    train_val_split = []
    test_split = []
    
    for r in data_records:
        if r.get(entity_key) in holdout_entities:
            test_split.append(r)
        else:
            train_val_split.append(r)
            
    # Chronologically split the remaining train_val
    train_split, val_split, _ = generate_chronological_splits(train_val_split, train_ratio=0.8, val_ratio=0.2)
    
    return train_split, val_split, test_split

def write_split_manifest(split_name, data, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{split_name}.json")
    with open(out_path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"Wrote {len(data)} records to {out_path}")

def run_dummy_test():
    """
    Dummy test to demonstrate the exit criteria.
    """
    print("Running data splitting test...")
    dummy_data = [
        {"id": i, "timestamp": 1600000000 + i, "src_ip": f"10.0.0.{i%5}"} 
        for i in range(100)
    ]
    
    train, val, test = generate_chronological_splits(dummy_data)
    
    # Check for overlapping timestamps
    max_train_ts = max([r['timestamp'] for r in train])
    min_val_ts = min([r['timestamp'] for r in val])
    max_val_ts = max([r['timestamp'] for r in val])
    min_test_ts = min([r['timestamp'] for r in test])
    
    assert max_train_ts < min_val_ts, "Train and Val splits overlap chronologically!"
    assert max_val_ts < min_test_ts, "Val and Test splits overlap chronologically!"
    print("SUCCESS: No overlapping timestamps across splits.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="Run the dummy chronological test")
    args = parser.parse_args()
    
    if args.test:
        run_dummy_test()
