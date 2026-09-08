"""
inference/worker.py

Kafka → ONNX Inference → Kafka pipeline worker.

Consumes "raw-features" topic, runs all ONNX models concurrently using
ONNX Runtime (CPU-optimized with inter-op parallelism), and publishes
normalized alerts to "alerts-normalized" topic.

Architecture:
  [raw-features] → deserialize → batch accumulator →
  ONNX Runtime (all models in parallel threads) →
  AlertNormalizer + AlertCorrelator → [alerts-normalized] → AlertStore (ClickHouse)
"""

import os
import sys
import json
import time
import logging
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

# Silence sklearn feature name warnings
import warnings
warnings.simplefilter('ignore', UserWarning)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from confluent_kafka import Consumer, Producer, KafkaError
from alerting.normalizer import AlertNormalizer
from alerting.correlator import AlertCorrelator
from alerting.store import ClickHouseAlertStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("inference.worker")

KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "kafka:9092")
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
ONNX_MODELS_DIR = os.environ.get("ONNX_MODELS_DIR", "/app/models/train/onnx")
BATCH_SIZE = int(os.environ.get("INFERENCE_BATCH_SIZE", "256"))
MAX_WORKERS = int(os.environ.get("INFERENCE_WORKERS", str(max(1, os.cpu_count() - 1))))

# ─────────────────────────────────────────────────────────────────────────────
# ONNX Model Manager
# ─────────────────────────────────────────────────────────────────────────────

class ONNXModelManager:
    """
    Loads all exported ONNX models and exposes a thread-safe batch predict API.
    Uses ONNX Runtime's built-in CPU parallelism for maximum throughput.
    """

    def __init__(self, models_dir: str):
        try:
            import onnxruntime as ort
        except ImportError:
            raise RuntimeError("onnxruntime not installed. Run: pip install onnxruntime")

        # Optimize for throughput: maximize inter-op parallelism
        sess_opts = ort.SessionOptions()
        sess_opts.inter_op_num_threads = MAX_WORKERS
        sess_opts.intra_op_num_threads = 2
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        sess_opts.enable_mem_pattern = True

        self.sessions = {}
        model_files = {
            "ddos":      "ddos_lgbm.onnx",
            "beaconing": "beaconing_ocsvm.onnx",
            "dga":       "dga_gbt.onnx",
            "encrypted": "encrypted_rf.onnx",
            "recon":     "recon_iso.onnx",
            "exfil":     "exfil_iso.onnx",
        }

        for name, filename in model_files.items():
            path = os.path.join(models_dir, filename)
            if os.path.exists(path):
                self.sessions[name] = ort.InferenceSession(path, sess_options=sess_opts)
                logger.info(f"Loaded ONNX model: {name} from {path}")
            else:
                logger.warning(f"ONNX model not found, skipping: {path}")

    def predict_batch(self, model_name: str, feature_batch: list) -> list:
        """
        Run batch inference for a given model.
        Returns list of (score, is_anomaly) tuples.
        """
        sess = self.sessions.get(model_name)
        if sess is None:
            return [(0.0, False)] * len(feature_batch)

        import numpy as np
        try:
            X = np.array(feature_batch, dtype=np.float32)
            input_name = sess.get_inputs()[0].name
            outputs = sess.run(None, {input_name: X})

            # ONNX classifiers output [labels, probabilities]
            # Anomaly detectors output [-1/1] labels
            if len(outputs) >= 2 and hasattr(outputs[1], '__len__'):
                # Classifier: probability of anomaly class
                probs = outputs[1]
                return [(float(p[1] if len(p) > 1 else p[0]), float(p[1] if len(p) > 1 else p[0]) > 0.5)
                        for p in probs]
            else:
                # Isolation forest / OCSVM: -1 = anomaly
                labels = outputs[0]
                return [(1.0 if l == -1 else 0.0, l == -1) for l in labels]
        except Exception as e:
            logger.error(f"ONNX inference error for {model_name}: {e}")
            return [(0.0, False)] * len(feature_batch)


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction from Kafka message
# ─────────────────────────────────────────────────────────────────────────────

def extract_features_for_model(model_name: str, record: dict) -> Optional[list]:
    """
    Map a raw-features JSON record to a numpy-ready feature vector for each model.
    Mirrors the feature schemas used during training.
    """
    try:
        if model_name == "ddos":
            return [
                record.get("pkt_rate_1s", 0.0),
                record.get("byte_rate_1s", 0.0),
                record.get("syn_rate_1s", 0.0),
                record.get("unique_dst_ports_1s", 0),
                record.get("ip_len", 0),
                record.get("tcp_flags", 0),
                record.get("flow_pkt_count", 0),
                record.get("flow_byte_count", 0),
            ]
        elif model_name == "recon":
            return [
                record.get("unique_ports_scanned", 0),
                record.get("pkt_rate_1s", 0.0),
                1 if record.get("is_port_scan", False) else 0,
                record.get("flow_duration", 0.0),
                record.get("tcp_flags", 0),
            ]
        elif model_name in ("beaconing", "exfil", "encrypted"):
            return [
                record.get("flow_duration", 0.0),
                record.get("flow_pkt_count", 0),
                record.get("flow_byte_count", 0),
                record.get("byte_rate_1s", 0.0),
                record.get("pkt_rate_1s", 0.0),
            ]
        else:
            return None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Kafka → inference → Kafka pipeline
# ─────────────────────────────────────────────────────────────────────────────

class InferenceWorker:
    def __init__(self):
        self.consumer = Consumer({
            "bootstrap.servers": KAFKA_BROKER,
            "group.id": "inference-workers",
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
            "fetch.min.bytes": 65536,         # Batch fetch for throughput
            "fetch.wait.max.ms": 10,
        })
        self.producer = Producer({
            "bootstrap.servers": KAFKA_BROKER,
            "queue.buffering.max.ms": "5",
            "batch.num.messages": "10000",
            "compression.type": "lz4",
        })
        self.model_mgr = ONNXModelManager(ONNX_MODELS_DIR)
        self.normalizer = AlertNormalizer()
        self.correlator = AlertCorrelator(time_window_seconds=600)
        self.store = ClickHouseAlertStore(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT)
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self._stop = threading.Event()

    def run(self):
        self.consumer.subscribe(["raw-features"])
        logger.info(f"Inference worker online. Batch size: {BATCH_SIZE}, Workers: {MAX_WORKERS}")

        pending: dict[str, list] = {m: [] for m in self.model_mgr.sessions}
        pending_meta: dict[str, list] = {m: [] for m in self.model_mgr.sessions}

        while not self._stop.is_set():
            msg = self.consumer.poll(timeout=0.05)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error(f"Consumer error: {msg.error()}")
                continue

            try:
                record = json.loads(msg.value())
            except json.JSONDecodeError:
                continue

            # Accumulate features into per-model batches
            for model_name in self.model_mgr.sessions:
                feats = extract_features_for_model(model_name, record)
                if feats:
                    pending[model_name].append(feats)
                    pending_meta[model_name].append(record)

            # Flush batch when full
            if any(len(v) >= BATCH_SIZE for v in pending.values()):
                self._flush_batch(pending, pending_meta)
                pending = {m: [] for m in self.model_mgr.sessions}
                pending_meta = {m: [] for m in self.model_mgr.sessions}

        # Final flush
        if any(pending.values()):
            self._flush_batch(pending, pending_meta)

        self.consumer.close()
        self.producer.flush()
        self.store.close()

    def _flush_batch(self, pending: dict, pending_meta: dict):
        """Run all models on their batches in parallel, then normalize and publish alerts."""
        futures = {}
        for model_name, batch in pending.items():
            if batch:
                futures[model_name] = self.executor.submit(
                    self.model_mgr.predict_batch, model_name, batch
                )

        for model_name, future in futures.items():
            try:
                results = future.result(timeout=2.0)
                for idx, (score, is_anomaly) in enumerate(results):
                    if is_anomaly and score > 0.5:
                        meta = pending_meta[model_name][idx]
                        flow_info = {
                            "src_ip": meta.get("src_ip", "0.0.0.0"),
                            "dst_ip": meta.get("dst_ip", "0.0.0.0"),
                            "src_port": meta.get("src_port", 0),
                            "dst_port": meta.get("dst_port", 0),
                            "protocol": meta.get("protocol", "TCP"),
                            "ip_len": meta.get("ip_len", 0),
                        }
                        alert = self.normalizer.normalize(
                            detector_name=model_name,
                            raw_score=score,
                            feature_values={k: meta.get(k, 0) for k in
                                            ["pkt_rate_1s", "byte_rate_1s", "syn_rate_1s",
                                             "flow_duration", "flow_pkt_count"]},
                            explanation=f"ONNX {model_name} anomaly score={score:.3f}",
                            flow_info=flow_info,
                            timestamp=meta.get("timestamp", time.time()),
                        )
                        correlated = self.correlator.process(alert)
                        self.store.append(correlated)

                        # Publish to Kafka for SSE stream
                        alert_dict = correlated.__dict__ if hasattr(correlated, '__dict__') else {}
                        self.producer.produce(
                            "alerts-normalized",
                            value=json.dumps(alert_dict, default=str).encode()
                        )
            except Exception as e:
                logger.error(f"Batch inference error for {model_name}: {e}")

        self.producer.poll(0)

    def stop(self):
        self._stop.set()


if __name__ == "__main__":
    worker = InferenceWorker()
    try:
        worker.run()
    except KeyboardInterrupt:
        worker.stop()
