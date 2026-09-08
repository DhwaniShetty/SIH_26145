import json
import os
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    manifest_path = os.path.join(os.path.dirname(__file__), 'manifest.json')
    if not os.path.exists(manifest_path):
        logging.error(f"Manifest not found at {manifest_path}")
        return

    with open(manifest_path, 'r') as f:
        manifest = json.load(f)

    for dataset in manifest.get('datasets', []):
        logging.info(f"Processing dataset: {dataset['name']} ({dataset['id']})")
        logging.info(f"  Source: {dataset['source']}")
        logging.info(f"  License: {dataset['license']}")
        
        if 'download_url' in dataset:
            url = dataset['download_url']
            logging.info(f"  Found direct download URL: {url}")
            # Note: We don't automatically download large PCAPs here to save disk/bandwidth 
            # unless specifically requested. For smaller feeds like DGA, we could.
            if dataset['id'] == 'dga-corpus':
                try:
                    target_file = os.path.join(os.path.dirname(__file__), 'dga_corpus.txt')
                    if not os.path.exists(target_file):
                        logging.info(f"  Downloading {url} to {target_file}...")
                        urllib.request.urlretrieve(url, target_file)
                        logging.info("  Download complete.")
                    else:
                        logging.info("  File already exists, skipping download.")
                except Exception as e:
                    logging.error(f"  Failed to download: {e}")
        elif 'download_instructions' in dataset:
            logging.info(f"  Manual instructions: {dataset['download_instructions']}")
        
        print("-" * 50)

if __name__ == "__main__":
    main()
