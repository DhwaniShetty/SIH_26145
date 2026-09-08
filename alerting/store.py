import sqlite3
import json
import os
from typing import List, Optional
from alerting.schema import AlertRecord
from alerting.webhook import WebhookNotifier

class AlertStore:
    def __init__(self, db_path="alerts.db", webhook_url: Optional[str] = None):
        self.db_path = db_path
        self._init_db()
        self.notifier = WebhookNotifier(webhook_url=webhook_url)
        
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
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
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_detector ON alerts(detector)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)')
        
        conn.commit()
        conn.close()
        
    def append(self, alert: AlertRecord):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (
                alert_id, timestamp, detector, threat_class, severity, 
                confidence_score, flow_id_json, evidence_json, related_alert_ids_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.alert_id,
            alert.timestamp,
            alert.detector,
            alert.threat_class,
            alert.severity,
            alert.confidence_score,
            alert.flow_id.model_dump_json(),
            alert.evidence.model_dump_json(),
            json.dumps(alert.related_alert_ids)
        ))
        
        conn.commit()
        conn.close()
        
        # Fire webhook if applicable
        self.notifier.notify(alert)
        
    def read_alerts(self, 
                    start_time: Optional[float] = None, 
                    end_time: Optional[float] = None, 
                    detector: Optional[str] = None, 
                    severity: Optional[str] = None) -> List[AlertRecord]:
        conn = sqlite3.connect(self.db_path)
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
        conn.close()
        
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
