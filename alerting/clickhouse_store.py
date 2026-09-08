"""
alerting/clickhouse_store.py

High-throughput alert store backed by ClickHouse.
Replaces the SQLite AlertStore for 50k PPS production workloads.

ClickHouse handles millions of inserts/second and sub-second analytical
queries — perfect for the /api/stats/summary endpoint that aggregates
threat rates, top talkers, and time-series data.
"""

import os
import json
import time
import logging
import threading
from typing import Optional

logger = logging.getLogger("alerting.clickhouse_store")

# DDL to create the alerts table in ClickHouse (run once on startup)
CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id     String,
    timestamp    Float64,
    threat_class String,
    severity     String,
    confidence   Float32,
    src_ip       String,
    dst_ip       String,
    src_port     UInt16,
    dst_port     UInt16,
    protocol     String,
    explanation  String,
    features     String,    -- JSON blob
    related_ids  String,    -- JSON array of related alert IDs
    inserted_at  DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (timestamp, threat_class)
TTL toDateTime(timestamp) + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;
"""

CREATE_TELEMETRY_TABLE = """
CREATE TABLE IF NOT EXISTS telemetry_log (
    ts           Float64,
    pkts_per_sec UInt64,
    mbps         Float32,
    active_flows UInt32,
    latency_ms   Float32,
    status       String
) ENGINE = MergeTree()
ORDER BY ts
TTL toDateTime(ts) + INTERVAL 1 DAY;
"""


class ClickHouseAlertStore:
    """
    Thread-safe, batched alert store backed by ClickHouse.

    Uses a background writer thread with configurable batch size and flush
    interval to amortize insert overhead across thousands of alerts.
    """

    def __init__(
        self,
        host: str = "clickhouse",
        port: int = 9000,
        database: str = "default",
        batch_size: int = 500,
        flush_interval_s: float = 0.5,
    ):
        self.host = host
        self.port = port
        self.database = database
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s

        self._pending: list = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._client = None

        self._connect()
        self._ensure_schema()

        self._writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._writer_thread.start()

    def _connect(self):
        try:
            from clickhouse_driver import Client
            self._client = Client(host=self.host, port=self.port, database=self.database)
            logger.info(f"Connected to ClickHouse at {self.host}:{self.port}")
        except ImportError:
            logger.error("clickhouse-driver not installed. Run: pip install clickhouse-driver")
            self._client = None
        except Exception as e:
            logger.error(f"ClickHouse connection failed: {e}")
            self._client = None

    def _ensure_schema(self):
        if not self._client:
            return
        try:
            self._client.execute(CREATE_ALERTS_TABLE)
            self._client.execute(CREATE_TELEMETRY_TABLE)
            logger.info("ClickHouse schema ready.")
        except Exception as e:
            logger.error(f"Schema creation failed: {e}")

    def append(self, alert):
        """Thread-safe: add an alert to the pending batch."""
        with self._lock:
            self._pending.append(alert)
            if len(self._pending) >= self.batch_size:
                self._flush_locked()

    def _writer_loop(self):
        """Background thread: flush pending alerts every flush_interval_s."""
        while not self._stop.is_set():
            time.sleep(self.flush_interval_s)
            with self._lock:
                if self._pending:
                    self._flush_locked()

    def _flush_locked(self):
        """Must be called with self._lock held."""
        if not self._client or not self._pending:
            return

        rows = []
        for a in self._pending:
            try:
                flow = getattr(a, 'flow_id', {})
                if hasattr(flow, '__dict__'): flow = flow.__dict__
                evidence = getattr(a, 'evidence', {})
                if hasattr(evidence, '__dict__'): evidence = evidence.__dict__

                rows.append({
                    "alert_id":    str(getattr(a, 'alert_id', '')),
                    "timestamp":   float(getattr(a, 'timestamp', time.time())),
                    "threat_class": str(getattr(a, 'threat_class', 'UNKNOWN')),
                    "severity":    str(getattr(a, 'severity', 'MEDIUM')),
                    "confidence":  float(getattr(a, 'confidence_score', 0.0)),
                    "src_ip":      str(flow.get('src_ip', '0.0.0.0')),
                    "dst_ip":      str(flow.get('dst_ip', '0.0.0.0')),
                    "src_port":    int(flow.get('src_port', 0)),
                    "dst_port":    int(flow.get('dst_port', 0)),
                    "protocol":    str(flow.get('protocol', 'TCP')),
                    "explanation": str(evidence.get('explanation', '')),
                    "features":    json.dumps(evidence.get('features', {}), default=str),
                    "related_ids": json.dumps(getattr(a, 'related_alert_ids', []), default=str),
                })
            except Exception as e:
                logger.warning(f"Skipping malformed alert: {e}")

        if not rows:
            self._pending.clear()
            return

        try:
            self._client.execute(
                "INSERT INTO alerts VALUES",
                [{
                    "alert_id": r["alert_id"],
                    "timestamp": r["timestamp"],
                    "threat_class": r["threat_class"],
                    "severity": r["severity"],
                    "confidence": r["confidence"],
                    "src_ip": r["src_ip"],
                    "dst_ip": r["dst_ip"],
                    "src_port": r["src_port"],
                    "dst_port": r["dst_port"],
                    "protocol": r["protocol"],
                    "explanation": r["explanation"],
                    "features": r["features"],
                    "related_ids": r["related_ids"],
                } for r in rows]
            )
            self._pending.clear()
        except Exception as e:
            logger.error(f"ClickHouse insert failed: {e}")

    def flush(self):
        with self._lock:
            self._flush_locked()

    def close(self):
        self._stop.set()
        self._writer_thread.join(timeout=3.0)
        self.flush()

    # ── Read API (mirrors AlertStore interface for backward compat) ──────────

    def read_alerts(self, limit: int = 50, severity: Optional[str] = None) -> list:
        if not self._client:
            return []
        try:
            where = f"WHERE severity = '{severity}'" if severity else ""
            rows = self._client.execute(
                f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT {limit}"
            )
            return rows
        except Exception as e:
            logger.error(f"ClickHouse read_alerts failed: {e}")
            return []

    def get_summary(self) -> dict:
        if not self._client:
            return {"total": 0, "rate_by_class": {}, "top_talkers": []}
        try:
            total = self._client.execute("SELECT count() FROM alerts")[0][0]
            by_class = self._client.execute(
                "SELECT threat_class, count() as cnt FROM alerts GROUP BY threat_class ORDER BY cnt DESC"
            )
            talkers = self._client.execute(
                "SELECT src_ip, count() as cnt FROM alerts GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
            )
            return {
                "total": total,
                "rate_by_class": {r[0]: r[1] for r in by_class},
                "top_talkers": [{"ip": r[0], "count": r[1]} for r in talkers],
            }
        except Exception as e:
            logger.error(f"ClickHouse get_summary failed: {e}")
            return {"total": 0, "rate_by_class": {}, "top_talkers": []}
