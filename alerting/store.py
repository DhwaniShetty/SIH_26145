import sqlite3
import json
import os
import threading
from typing import List, Optional, Tuple, Dict, Any
from alerting.schema import AlertRecord
from alerting.webhook import WebhookNotifier

class AlertStore:
    """
    High-performance, thread-safe SQLite alert sink.
    Features:
    - WAL (Write-Ahead Log) mode for concurrent read/write throughput
    - In-memory micro-batching to eliminate per-alert fsync disk bottlenecks
    - Background asynchronous webhook dispatching
    - Fast batch insert via append_batch()
    """
    def __init__(self, db_path="alerts.db", webhook_url: Optional[str] = None, batch_size: int = 50):
        self.db_path = db_path
        self.batch_size = batch_size
        self._lock = threading.Lock()
        self._write_buffer: List[AlertRecord] = []
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()
        self.notifier = WebhookNotifier(webhook_url=webhook_url)
        
    def _get_connection(self) -> sqlite3.Connection:
        """Returns or initializes a persistent connection configured with WAL mode."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode = WAL;")
            self._conn.execute("PRAGMA synchronous = NORMAL;")
            self._conn.execute("PRAGMA cache_size = -64000;")  # 64MB cache
            self._conn.execute("PRAGMA temp_store = MEMORY;")
        return self._conn

    def _init_db(self):
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp REAL,
                    detector TEXT,
                    threat_class TEXT,
                    severity TEXT,
                    confidence_score REAL,
                    flow_id_json TEXT,
                    evidence_json TEXT,
                    related_alert_ids_json TEXT
                )
            ''')
            
            # Create indexes for rapid filtering and querying
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_detector ON alerts(detector)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)')
            
            conn.commit()

    def clear(self):
        """Safely clears all records from the alerts table and compacts the database."""
        with self._lock:
            self._write_buffer.clear()
            conn = self._get_connection()
            conn.execute("DELETE FROM alerts;")
            conn.commit()
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                conn.execute("VACUUM;")
            except Exception:
                pass
            
    def append(self, alert: AlertRecord):
        """
        Appends an alert to the store.
        Uses in-memory micro-batching to prevent per-alert disk fsync blocking.
        """
        with self._lock:
            self._write_buffer.append(alert)
            if len(self._write_buffer) >= self.batch_size:
                self._flush_locked()
        
        # Fire webhook asynchronously so network latency never blocks packet ingestion
        if self.notifier.webhook_url:
            threading.Thread(target=self.notifier.notify, args=(alert,), daemon=True).start()

    def append_batch(self, alerts: List[AlertRecord]):
        """Fast bulk insert of multiple alerts in a single transaction."""
        if not alerts:
            return
        with self._lock:
            self._write_buffer.extend(alerts)
            self._flush_locked()

    def flush(self):
        """Explicitly flushes any pending buffered alerts to disk."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self):
        """Flushes write buffer within an acquired lock."""
        if not self._write_buffer:
            return

        conn = self._get_connection()
        records = [
            (
                a.alert_id,
                a.timestamp,
                a.detector,
                a.threat_class,
                a.severity,
                a.confidence_score,
                a.flow_id.model_dump_json(),
                a.evidence.model_dump_json(),
                json.dumps(a.related_alert_ids)
            )
            for a in self._write_buffer
        ]
        
        try:
            conn.executemany('''
                INSERT OR IGNORE INTO alerts (
                    alert_id, timestamp, detector, threat_class, severity, 
                    confidence_score, flow_id_json, evidence_json, related_alert_ids_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', records)
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self._write_buffer.clear()
            
    def read_alerts(self, 
                    start_time: Optional[float] = None, 
                    end_time: Optional[float] = None, 
                    detector: Optional[str] = None, 
                    severity: Optional[str] = None) -> List[AlertRecord]:
        """Reads alerts with automatic flushing of pending buffered writes."""
        # Ensure any pending writes are committed before read
        self.flush()

        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if start_time is not None:
                query += " AND timestamp >= ?"
                params.append(start_time)
            if end_time is not None:
                query += " AND timestamp <= ?"
                params.append(end_time)
            if detector is not None:
                query += " AND detector = ?"
                params.append(detector)
            if severity is not None:
                query += " AND severity = ?"
                params.append(severity)
                
            query += " ORDER BY timestamp ASC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
        alerts = []
        for row in rows:
            alert = AlertRecord(
                alert_id=row[0],
                timestamp=row[1],
                detector=row[2],
                threat_class=row[3],
                severity=row[4],
                confidence_score=row[5],
                flow_id=json.loads(row[6]),
                evidence=json.loads(row[7]),
                related_alert_ids=json.loads(row[8])
            )
            alerts.append(alert)
            
        return alerts

    def get_alert_by_id(self, alert_id: str) -> Optional[AlertRecord]:
        """Direct index lookup for a specific alert by primary key in O(1)."""
        self.flush()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE alert_id = ? LIMIT 1", (alert_id,))
            row = cursor.fetchone()

        if not row:
            return None

        return AlertRecord(
            alert_id=row[0],
            timestamp=row[1],
            detector=row[2],
            threat_class=row[3],
            severity=row[4],
            confidence_score=row[5],
            flow_id=json.loads(row[6]),
            evidence=json.loads(row[7]),
            related_alert_ids=json.loads(row[8])
        )

    def read_alerts_paginated(self, 
                              limit: int = 100, 
                              offset: int = 0, 
                              detector: Optional[str] = None, 
                              severity: Optional[str] = None) -> Tuple[int, List[AlertRecord]]:
        """
        High-performance SQL paginated alert fetch (newest first).
        Returns (total_matching_count, paginated_alert_records).
        Only deserializes the requested window of alerts rather than the full table.
        """
        self.flush()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            where_clauses = ["1=1"]
            params = []
            if detector is not None:
                where_clauses.append("detector = ?")
                params.append(detector)
            if severity is not None:
                where_clauses.append("severity = ?")
                params.append(severity)
                
            where_str = " AND ".join(where_clauses)
            
            # Count matching rows
            cursor.execute(f"SELECT COUNT(*) FROM alerts WHERE {where_str}", params)
            total = cursor.fetchone()[0]
            
            # Fetch slice ordered newest first
            cursor.execute(
                f"SELECT * FROM alerts WHERE {where_str} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            )
            rows = cursor.fetchall()
            
        alerts = [
            AlertRecord(
                alert_id=r[0],
                timestamp=r[1],
                detector=r[2],
                threat_class=r[3],
                severity=r[4],
                confidence_score=r[5],
                flow_id=json.loads(r[6]),
                evidence=json.loads(r[7]),
                related_alert_ids=json.loads(r[8])
            )
            for r in rows
        ]
        return total, alerts

    def get_summary_stats(self) -> Dict[str, Any]:
        """
        Executes sub-millisecond SQL aggregations directly inside SQLite engine.
        Bypasses deserialization of full AlertRecord objects into Python memory.
        """
        self.flush()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # 1. Total alerts count
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]
            
            # 2. Rate grouped by threat class
            cursor.execute("SELECT threat_class, COUNT(*) FROM alerts GROUP BY threat_class")
            rate_by_class = {row[0]: row[1] for row in cursor.fetchall()}
            
            # 3. Top talkers via native SQLite json_extract on flow_id_json
            cursor.execute("""
                SELECT json_extract(flow_id_json, '$.src_ip') AS src, COUNT(*) AS cnt 
                FROM alerts 
                WHERE src IS NOT NULL 
                GROUP BY src 
                ORDER BY cnt DESC 
                LIMIT 10
            """)
            top_talkers = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
            
        return {
            "rate_by_class": rate_by_class,
            "top_talkers": top_talkers,
            "total_alerts": total_alerts
        }

    def close(self):
        """Flushes remaining writes and closes the database connection."""
        with self._lock:
            self._flush_locked()
            if self._conn:
                self._conn.close()
                self._conn = None
