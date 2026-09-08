# Data Staging

This directory contains scripts and manifests for fetching and staging external datasets required for the threat detection project.

## Files
- `manifest.json`: Contains metadata about external datasets (CIC-IDS, CTU-13, DGA, etc.), including licenses and download URLs or instructions.
- `fetch_datasets.py`: A script to parse the manifest, print instructions for manually downloaded datasets, and automatically download accessible open feeds (like DGA corpora).
- `splits/`: Contains scripts and metadata for splitting the datasets into chronological train/validation/test sets, preserving entity holdouts.

## Instructions
1. Run `python fetch_datasets.py` from this directory.
2. Follow the printed instructions to download larger datasets (like CIC-IDS and CTU-13 PCAPs) directly from their sources into this directory.
3. Once PCAPs are placed in this directory or subdirectories, they can be used by the pipeline.
