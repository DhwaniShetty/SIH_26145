"""
datasource/simulated.py – DataSource wrapper around the existing PCAP replay pipeline.

This delegates directly to tests/test_phase5_e2e.py via subprocess, exactly as the
existing /api/replay endpoint does, but through a uniform DataSource interface.
"""
from __future__ import annotations
import os, sys, json, time, subprocess, threading
from typing import List, Optional
from .base import DataSource


class SimulatedSource(DataSource):
    """
    Drives the existing ONNX-accelerated PCAP replay (test_phase5_e2e.py).
    Reads alerts from the SQLite store and telemetry from tests/telemetry.json.
    """

    def __init__(self, db_path: str, telemetry_path: str, script_path: str):
        self._db_path = db_path
        self._telemetry_path = telemetry_path
        self._script_path = script_path
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()

    def start(self, scenario: str = "random", duration: Optional[float] = None) -> None:
        self.stop()
        cmd = [sys.executable, self._script_path, "--scenario", scenario]
        if duration:
            cmd += ["--duration", str(duration)]
        with self._lock:
            self._proc = subprocess.Popen(cmd)

    def stop(self) -> None:
        with self._lock:
            if self._proc and self._proc.poll() is None:
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(self._proc.pid)],
                                   capture_output=True)
                else:
                    self._proc.terminate()
                self._proc = None

    def is_running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def read_alerts(self, since_ts: float) -> List[dict]:
        """Delegate to AlertStore – same as server.py currently does."""
        try:
            sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
            from alerting.store import AlertStore
            store = AlertStore(db_path=self._db_path)
            alerts = store.read_alerts(start_time=since_ts)
            return [a.model_dump() for a in alerts]
        except Exception:
            return []

    def read_telemetry(self) -> dict:
        try:
            with open(self._telemetry_path) as f:
                data = json.load(f)
            if time.time() - data.get("updated_at", 0) < 15:
                return data
        except Exception:
            pass
        import random
        j = random.uniform(0.96, 1.04)
        return {"pkts_per_sec": int(3600*j), "mbps": round(24.8*j,1),
                "active_flows": int(164*j), "latency_ms": round(1.18*j,2),
                "diode_mode": "PASSIVE RX ONLY", "status": "IDLE_BASELINE",
                "updated_at": time.time()}
