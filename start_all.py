import subprocess
import os
import sys
import webbrowser
import time
import argparse
import urllib.request
import urllib.error
import socket
import signal
import atexit
from typing import Optional

REQUIRED_DATASETS = [
    "benign.pcap",
    "c2_beacon.pcap",
    "dns_tunnel.pcap",
    "port_scan_horizontal.pcap",
    "syn_flood.pcap",
    "udp_amplification.pcap"
]

REQUIRED_MODELS = [
    "ddos_lgbm.pkl",
    "beaconing_ocsvm.pkl",
    "dga_gbt.pkl",
    "dga_lstm.pt",
    "encrypted_rf.pkl",
    "exfil_iso.pkl",
    "recon_iso.pkl"
]

def kill_process_tree(pid: int):
    """Recursively terminates all child and descendant processes across Windows and POSIX."""
    try:
        import psutil
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        try:
            parent.terminate()
        except psutil.NoSuchProcess:
            pass

        gone, alive = psutil.wait_procs(children + [parent], timeout=1.5)
        for proc in alive:
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                pass
    except Exception:
        # Fallback for Windows if psutil has issues with access rights
        if sys.platform == "win32":
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
            except Exception:
                pass

def check_port_in_use(port: int) -> Optional[int]:
    """Checks if a port is bound and attempts to discover the PID using it."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            result = s.connect_ex(('127.0.0.1', port))
            if result != 0:
                return None
    except Exception:
        return None

    # Port is open: identify the PID via psutil
    try:
        import psutil
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                return conn.pid
    except Exception:
        pass
    return -1

def ensure_port_available(port: int) -> bool:
    """Detects and resolves port collisions before launching the server."""
    pid = check_port_in_use(port)
    if pid is None:
        return True

    print(f"[{time.strftime('%H:%M:%S')}] Warning: Port {port} is already in use (PID: {pid if pid != -1 else 'unknown'}).")
    if pid and pid != -1:
        print(f"[{time.strftime('%H:%M:%S')}] Automatically terminating stale listener on port {port} (PID: {pid})...")
        kill_process_tree(pid)
        time.sleep(0.6)
        if check_port_in_use(port) is None:
            print(f"[{time.strftime('%H:%M:%S')}] Successfully reclaimed port {port}.")
            return True
    return False

class ProcessSupervisor:
    """Supervises the Dashboard API child process tree and guarantees clean termination."""
    def __init__(self, process: subprocess.Popen):
        self.process = process
        self._terminated = False
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        atexit.register(self.shutdown)

    def _handle_signal(self, signum, frame):
        print(f"\n[{time.strftime('%H:%M:%S')}] Received stop signal ({signum}). Initiating graceful teardown...")
        self.shutdown()
        sys.exit(0)

    def shutdown(self):
        if self._terminated:
            return
        self._terminated = True
        if self.process and self.process.poll() is None:
            print(f"[{time.strftime('%H:%M:%S')}] Terminating API server and all child processes...")
            kill_process_tree(self.process.pid)
            print(f"[{time.strftime('%H:%M:%S')}] Teardown complete. All processes exited cleanly.")

    def monitor(self):
        """Watchdog loop checking process health and exit codes."""
        try:
            while True:
                exit_code = self.process.poll()
                if exit_code is not None:
                    if exit_code != 0:
                        print(f"\n[{time.strftime('%H:%M:%S')}] ERROR: Dashboard API exited unexpectedly with code {exit_code}.", file=sys.stderr)
                    else:
                        print(f"\n[{time.strftime('%H:%M:%S')}] Dashboard API server closed.")
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.shutdown()
            sys.exit(0)

def run_script(script_path: str):
    """Executes a python script and exits if it fails."""
    script_name = os.path.basename(script_path)
    t0 = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] Running {script_name}...")
    try:
        subprocess.run([sys.executable, script_path], check=True)
        elapsed = time.time() - t0
        print(f"[{time.strftime('%H:%M:%S')}] Finished {script_name} in {elapsed:.2f}s\n")
    except subprocess.CalledProcessError as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error while running {script_name}: {e}\n", file=sys.stderr)
        sys.exit(1)

def check_existing_assets(root_dir: str):
    """Checks for existing dataset PCAPs and serialized ML models."""
    data_dir = os.path.join(root_dir, "data")
    results_dir = os.path.join(root_dir, "models", "train", "results")

    missing_data = [f for f in REQUIRED_DATASETS if not os.path.exists(os.path.join(data_dir, f))]
    missing_models = [m for m in REQUIRED_MODELS if not os.path.exists(os.path.join(results_dir, m))]

    return missing_data, missing_models

def wait_for_server(url: str, timeout: float = 10.0) -> bool:
    """Polls server URL until it responds or timeout expires."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with urllib.request.urlopen(url, timeout=0.5) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.15)
    return False

def main():
    parser = argparse.ArgumentParser(description="Unidirectional AI Threat Detector Pipeline Launcher")
    parser.add_argument("--retrain", "-r", action="store_true", help="Force synthetic dataset re-generation and model retraining")
    parser.add_argument("--port", "-p", type=int, default=8000, help="Port to run Dashboard on (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the browser")
    args = parser.parse_args()

    root_dir = os.path.dirname(os.path.abspath(__file__))
    missing_data, missing_models = check_existing_assets(root_dir)

    needs_generation = args.retrain or len(missing_data) > 0
    needs_training = args.retrain or len(missing_models) > 0

    if not needs_generation and not needs_training:
        print("\n=======================================================")
        print("  [FAST LAUNCH] Pre-trained models and datasets detected!")
        print("  Skipping synthetic data generation and retraining.")
        print("  (Tip: Pass '--retrain' if you wish to retrain from scratch)")
        print("=======================================================\n")
    else:
        # Step 1: Generate Synthetic Data
        if needs_generation:
            print("=== Step 1: Generating Synthetic Data ===")
            traffic_gen_script = os.path.join(root_dir, "tools", "traffic_gen", "run_all.py")
            run_script(traffic_gen_script)
        else:
            print("=== Step 1: Datasets already exist. Skipping traffic generation. ===")

        # Step 2: Feature Extraction & Training
        if needs_training:
            print("=== Step 2: Feature Extraction & Model Training ===")
            train_scripts = [
                "dataset_generator.py",
                "ddos_train.py",
                "beaconing_train.py",
                "dga_train.py",
                "encrypted_train.py",
                "exfil_train.py",
                "recon_train.py"
            ]
            for script in train_scripts:
                script_path = os.path.join(root_dir, "models", "train", script)
                run_script(script_path)
        else:
            print("=== Step 2: All models already trained. Skipping training. ===")

    # Step 3: Resolve Port & Start Dashboard API
    print("=== Step 3: Starting Dashboard API ===")
    ensure_port_available(args.port)

    print(f"[{time.strftime('%H:%M:%S')}] Launching FastAPI via Uvicorn on port {args.port}...")
    api_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "dashboard.api.server:app", "--port", str(args.port)],
        cwd=root_dir
    )

    supervisor = ProcessSupervisor(api_process)

    # Step 4: Fast Health-Check Polling
    dashboard_url = f"http://127.0.0.1:{args.port}"
    api_health_url = f"{dashboard_url}/api/stats/summary"
    print(f"Waiting for backend API to initialize...")
    is_ready = wait_for_server(api_health_url, timeout=10.0)

    if is_ready:
        print(f"[{time.strftime('%H:%M:%S')}] API is healthy and ready!")
    else:
        print(f"[{time.strftime('%H:%M:%S')}] Server started.")

    # Step 5: Open Browser
    if not args.no_browser:
        print(f"=== Step 4: Opening Dashboard ===")
        print(f"Opening {dashboard_url} in your default browser...")
        webbrowser.open(dashboard_url)

    print("\n=======================================================")
    print(f"  ThreatDetect Dashboard running at: {dashboard_url}")
    print("  Press Ctrl+C here to terminate the API server.")
    print("=======================================================\n")

    supervisor.monitor()

if __name__ == "__main__":
    main()
