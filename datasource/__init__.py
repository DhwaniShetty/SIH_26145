"""
datasource package – modular data-source interface for Sentrix NOC pipeline.

Two concrete implementations ship out of the box:
  SimulatedSource     – wraps the existing PCAP-replay + ONNX inference pipeline
  DatasetReplaySource – streams pre-labeled flow records from CSV/JSON datasets
"""
from .base import DataSource, FlowRecord
from .simulated import SimulatedSource
from .dataset_replay import DatasetReplaySource

__all__ = ["DataSource", "FlowRecord", "SimulatedSource", "DatasetReplaySource"]
