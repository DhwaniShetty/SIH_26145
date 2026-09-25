#!/usr/bin/env python3
"""
scripts/extract_features.py
============================
Extracts flow-level features from PCAP files and writes a normalized CSV/Parquet
dataset consumable by DatasetReplaySource.

Backend auto-detection order:
  1. nfstream  (pip install nfstream)
  2. scapy     (already in requirements.txt)

Usage:
  # Single PCAP + label sidecar
  python scripts/extract_features.py \
      --pcap data/datasets/syn_flood/packets.pcap \
      --labels data/datasets/syn_flood/labels.json \
      --output data/datasets/syn_flood/features.csv

  # Batch: all attack subdirectories under data/datasets/
  python scripts/extract_features.py --input-dir data/datasets/ --output-dir data/datasets/

  # Force nfstream or scapy backend
  python scripts/extract_features.py --pcap ... --backend nfstream
"""
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from datasource.feature_extractor import extract_features


def batch_extract(input_dir: Path, output_dir: Path, backend: str) -> None:
    """Process every PCAP file found under input_dir (recurse one level)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    pcaps = list(input_dir.rglob("*.pcap"))
    if not pcaps:
        print(f"[extract_features] No PCAP files found under {input_dir}")
        return
    print(f"[extract_features] Found {len(pcaps)} PCAP files.  Backend: {backend}")
    for pcap_path in sorted(pcaps):
        label_path = pcap_path.parent / "labels.json"
        out_stem = pcap_path.parent.name  # e.g. "syn_flood"
        out_file = output_dir / f"{out_stem}_features.csv"
        print(f"  Processing: {pcap_path.name} -> {out_file.name}")
        try:
            rows = extract_features(
                pcap_path=str(pcap_path),
                label_path=str(label_path) if label_path.exists() else None,
                output_path=str(out_file),
                backend=backend,
            )
            print(f"    OK {len(rows)} flows extracted")
        except Exception as e:
            print(f"    [X] Error: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Flow feature extractor (nfstream/Scapy) -> CSV")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--pcap", type=Path, help="Single PCAP input file")
    grp.add_argument("--input-dir", type=Path, help="Directory to scan for PCAPs (batch mode)")
    parser.add_argument("--labels", type=Path, help="JSON label sidecar (single-file mode)")
    parser.add_argument("--output",     type=Path, help="Output CSV path (single-file mode)")
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "data" / "datasets",
                        help="Output directory (batch mode)")
    parser.add_argument("--backend", choices=["auto", "nfstream", "scapy"],
                        default="auto", help="Feature extraction backend")
    args = parser.parse_args()

    if args.pcap:
        out = args.output or (args.pcap.parent / (args.pcap.stem + "_features.csv"))
        rows = extract_features(
            pcap_path=str(args.pcap),
            label_path=str(args.labels) if args.labels else None,
            output_path=str(out),
            backend=args.backend,
        )
        print(f"[extract_features] Done — {len(rows)} flows → {out}")
    else:
        batch_extract(args.input_dir, args.output_dir, args.backend)


if __name__ == "__main__":
    main()
