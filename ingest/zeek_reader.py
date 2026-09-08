import os
import json
import subprocess
import threading
import queue
import logging

logger = logging.getLogger(__name__)

class ZeekJSONReader:
    """
    Reads a PCAP file by passing it through a Dockerized Zeek instance.
    Streams the resulting JSON logs (conn.log, dns.log, ssl.log) into a bounded queue.
    """
    def __init__(self, pcap_path, output_dir="zeek_logs"):
        self.pcap_path = os.path.abspath(pcap_path)
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        self.buffer = queue.Queue(maxsize=100000)
        self._stop_event = threading.Event()
        self._producer_thread = None

    def start(self):
        self._producer_thread = threading.Thread(target=self._ingest_loop, daemon=True)
        self._producer_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._producer_thread:
            self._producer_thread.join()

    def _ingest_loop(self):
        try:
            # Clean old logs
            for f in os.listdir(self.output_dir):
                if f.endswith('.log'):
                    os.remove(os.path.join(self.output_dir, f))
        except Exception:
            pass

        # Run Zeek via Docker
        pcap_dir = os.path.dirname(self.pcap_path)
        pcap_file = os.path.basename(self.pcap_path)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{pcap_dir}:/pcap",
            "-v", f"{self.output_dir}:/zeek_logs",
            "zeek/zeek:latest",
            "zeek", "-C", "-r", f"/pcap/{pcap_file}",
            "LogAscii::use_json=T", "Log::default_logdir=/zeek_logs"
        ]
        
        logger.info(f"Running Zeek on {pcap_file}...")
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Read conn.log
        conn_log = os.path.join(self.output_dir, "conn.log")
        if os.path.exists(conn_log):
            with open(conn_log, "r") as f:
                for line in f:
                    if self._stop_event.is_set():
                        break
                    try:
                        record = json.loads(line)
                        record['_log_type'] = 'conn'
                        self.buffer.put_nowait(record)
                    except queue.Full:
                        pass
                        
        # Read dns.log
        dns_log = os.path.join(self.output_dir, "dns.log")
        if os.path.exists(dns_log):
            with open(dns_log, "r") as f:
                for line in f:
                    if self._stop_event.is_set():
                        break
                    try:
                        record = json.loads(line)
                        record['_log_type'] = 'dns'
                        self.buffer.put_nowait(record)
                    except queue.Full:
                        pass

        # Read ssl.log
        ssl_log = os.path.join(self.output_dir, "ssl.log")
        if os.path.exists(ssl_log):
            with open(ssl_log, "r") as f:
                for line in f:
                    if self._stop_event.is_set():
                        break
                    try:
                        record = json.loads(line)
                        record['_log_type'] = 'ssl'
                        self.buffer.put_nowait(record)
                    except queue.Full:
                        pass
                        
        # Signal EOF
        self.buffer.put(None)

    def get_flow(self, timeout=0.05):
        try:
            return self.buffer.get(timeout=timeout)
        except queue.Empty:
            return None
