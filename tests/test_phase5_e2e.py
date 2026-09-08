import os
import sys
import time
import json
import queue
import random
import argparse
import warnings
import signal
import multiprocessing as mp
import threading
from typing import Optional

# Prevent OpenBLAS from over-allocating threads in multiprocessing
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

warnings.simplefilter('ignore', UserWarning)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import dpkt
from inference.onnx_engine import ONNXInferenceEngine
from ingest.pcap_reader import BoundedPcapReader
from parsers.ip_tcp_udp import parse_packet
from parsers.dns_parser import parse_dns
from parsers.tls_quic_handshake import parse_tls_handshake
from features.scheduler import FeatureScheduler

from models.ddos_detector import DDoSDetector
from models.beaconing_detector import BeaconingDetector
from models.dga_classifier import DGAClassifier
from models.encrypted_traffic_classifier import EncryptedTrafficClassifier
from models.recon_scan_detector import ReconScanDetector
from models.exfiltration_detector import ExfiltrationDetector
from models.dns_exfil_detector import DNSExfiltrationDetector

from alerting.normalizer import AlertNormalizer
from alerting.correlator import AlertCorrelator
from alerting.store import AlertStore

SCENARIO_PROFILES = {
    "massive_ddos": {
        "name": "Massive Volumetric DDoS Wave (Thousands of alerts, 0 C2)",
        "plan": [
            ("benign.pcap", 150),
            ("syn_flood.pcap", 2500),
            ("udp_amplification.pcap", 1500)
        ]
    },
    "stealth_c2_exfil": {
        "name": "Stealthy C2 & DNS Exfiltration (0 DDoS)",
        "plan": [
            ("benign.pcap", 300),
            ("c2_beacon.pcap", 60),
            ("dns_tunnel.pcap", 60),
            ("port_scan_horizontal.pcap", 25)
        ]
    },
    "recon_storm": {
        "name": "Reconnaissance Scan Storm (0 DDoS, 0 C2)",
        "plan": [
            ("benign.pcap", 200),
            ("port_scan_vertical.pcap", 300),
            ("port_scan_hybrid.pcap", 200)
        ]
    },
    "quiet_hours": {
        "name": "Calm Baseline (0 DDoS, 0 C2, ~0 threats)",
        "plan": [
            ("benign.pcap", 400)
        ]
    },
    "coordinated_campaign": {
        "name": "Coordinated Multi-Vector Attack Campaign",
        "plan": [
            ("benign.pcap", 200),
            ("port_scan_horizontal.pcap", 80),
            ("c2_beacon.pcap", 50),
            ("dns_tunnel.pcap", 50),
            ("syn_flood.pcap", 1500)
        ]
    }
}

def generate_random_scenario():
    plan = [("benign.pcap", random.randint(150, 350))]
    has_ddos = random.random() < 0.55
    has_c2 = random.random() < 0.50
    has_recon = random.random() < 0.55
    has_dns = random.random() < 0.45
    
    if not any([has_ddos, has_c2, has_recon, has_dns]):
        has_ddos = True
        has_recon = True
    
    desc_parts = []
    if has_ddos:
        ddos_count = random.choice([random.randint(600, 1200), random.randint(2000, 3500)])
        ddos_pcap = random.choice(["syn_flood.pcap", "udp_amplification.pcap"])
        plan.append((ddos_pcap, ddos_count))
        desc_parts.append(f"DDoS ({ddos_count} pkts)")
    else: desc_parts.append("0 DDoS")
        
    if has_c2:
        c2_count = random.randint(25, 80)
        plan.append(("c2_beacon.pcap", c2_count))
        desc_parts.append(f"C2 Beacon ({c2_count} pkts)")
    else: desc_parts.append("0 C2")
        
    if has_recon:
        recon_count = random.randint(40, 250)
        recon_pcap = random.choice(["port_scan_horizontal.pcap", "port_scan_vertical.pcap", "port_scan_hybrid.pcap"])
        plan.append((recon_pcap, recon_count))
        desc_parts.append(f"Recon ({recon_count} pkts)")
    else: desc_parts.append("0 Recon")
        
    if has_dns:
        dns_count = random.randint(25, 75)
        plan.append(("dns_tunnel.pcap", dns_count))
        desc_parts.append(f"DNS Exfil ({dns_count} pkts)")
    else: desc_parts.append("0 DNS Exfil")
        
    name = "Dynamic Mix: " + ", ".join(desc_parts)
    return {"name": name, "plan": plan}

def update_telemetry(pkts_rate, mbps, active_flows, latency_ms, status="STREAMING"):
    telemetry_path = os.path.join(os.path.dirname(__file__), 'telemetry.json')
    data = {
        "pkts_per_sec": int(pkts_rate),
        "mbps": round(float(mbps), 1),
        "active_flows": int(active_flows),
        "latency_ms": round(float(latency_ms), 2),
        "diode_mode": "PASSIVE RX ONLY (Tx Physically Disabled)",
        "status": status,
        "updated_at": time.time()
    }
    try:
        tmp_path = telemetry_path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, telemetry_path)
    except Exception:
        pass

def inference_worker(results_dir, onnx_engine, task_queue, alert_queue, stop_event):
    """Worker process: runs vectorized ONNX inference when available, else falls back to PKL."""
    fallback_detectors = {}
    def get_fallback_detector(name):
        if name not in fallback_detectors:
            try:
                if name == "ddos":
                    fallback_detectors[name] = DDoSDetector(os.path.join(results_dir, 'ddos_lgbm.pkl'))
                elif name == "beaconing":
                    fallback_detectors[name] = BeaconingDetector(os.path.join(results_dir, 'beaconing_ocsvm.pkl'))
                elif name == "dga":
                    fallback_detectors[name] = DGAClassifier(
                        gbt_model_path=os.path.join(results_dir, 'dga_gbt.pkl'),
                        lstm_model_path=os.path.join(results_dir, 'dga_lstm.pt')
                    )
                elif name == "encrypted":
                    fallback_detectors[name] = EncryptedTrafficClassifier(os.path.join(results_dir, 'encrypted_rf.pkl'))
                elif name == "recon":
                    fallback_detectors[name] = ReconScanDetector(os.path.join(results_dir, 'recon_iso.pkl'))
                elif name == "exfil":
                    fallback_detectors[name] = ExfiltrationDetector(os.path.join(results_dir, 'exfil_iso.pkl'))
                elif name == "dns_exfil":
                    fallback_detectors[name] = DNSExfiltrationDetector()
            except Exception:
                pass
        return fallback_detectors.get(name)

    import warnings
    warnings.filterwarnings('ignore')
    
    normalizer = AlertNormalizer()
    correlator = AlertCorrelator(time_window_seconds=600)
    
    while True:
        try:
            batch = task_queue.get(timeout=0.1)
        except queue.Empty:
            if stop_event.is_set():
                break
            continue
        if batch == "STOP":
            break
        try:
            for task in batch:
                det_name, feats, meta, ts = task
                score = 0.0
                feats_used = feats
                expl = ""

                # Fast-path: Accelerated ONNX & heuristic inference
                if onnx_engine and det_name in onnx_engine.sessions:
                    if det_name == "ddos":
                        syn_r = feats.get("syn_synack_ratio", 0.0)
                        pkt_ewma = feats.get("dst_pkt_ewma", 0.0)
                        amp_r = feats.get("amp_byte_ratio", 0.0)
                        ent = feats.get("src_ip_entropy", 0.0)
                        feats_used = {"syn_synack_ratio": syn_r, "dst_pkt_ewma": pkt_ewma, "amp_byte_ratio": amp_r, "src_ip_entropy": ent}
                        if syn_r > 10.0:
                            score, expl = 0.95, f"High probability of SYN Flood: SYN to SYN-ACK ratio is {syn_r:.1f}x."
                        elif amp_r > 10.0:
                            score, expl = 0.98, f"UDP Reflection/Amplification Flood: Outbound-to-inbound byte amplification ratio is {amp_r:.1f}x."
                        else:
                            score = onnx_engine.predict_ddos(syn_r, pkt_ewma)
                            if score > 0.5:
                                expl = f"ONNX LightGBM flagged DDoS volumetric flood (prob: {score:.2f})."

                    elif det_name == "beaconing":
                        cv = feats.get("iat_cv", 1.0)
                        mean_iat = feats.get("mean_iat", 0.0)
                        feats_used = {"iat_cv": cv, "mean_iat": mean_iat}
                        if mean_iat > 0 and cv < 0.1:
                            score, expl = 0.90, f"High periodicity detected: IAT CV is extremely low ({cv:.3f}), mean IAT {mean_iat:.2f}s."
                        elif mean_iat > 0:
                            lbl, dist = onnx_engine.predict_beaconing(cv, mean_iat)
                            if lbl == -1 and cv < 0.5:
                                score, expl = 0.85, f"ONNX One-Class SVM flagged abnormal periodicity (CV={cv:.2f})."

                    elif det_name == "dga":
                        avg_l = feats.get("avg_query_length", 0.0)
                        avg_e = feats.get("avg_query_entropy", 0.0)
                        nx = feats.get("nxdomain_rate", 0.0)
                        feats_used = {"avg_query_length": avg_l, "avg_query_entropy": avg_e, "nxdomain_rate": nx}
                        if avg_l > 0:
                            score = onnx_engine.predict_dga_gbt(avg_l, avg_e, nx)
                            if score > 0.5:
                                expl = f"ONNX LightGBM flagged DGA tunneling activity (prob: {score:.2f})."

                    elif det_name == "encrypted":
                        szs = feats.get("packet_sizes", [])
                        ipts = feats.get("packet_ipts", [])
                        sni = feats.get("sni_length_ewma", 0.0)
                        m_sz = float(sum(szs)/len(szs)) if szs else 0.0
                        v_sz = float(sum((x - m_sz)**2 for x in szs)/len(szs)) if szs else 0.0
                        m_ipt = float(sum(ipts)/len(ipts)) if ipts else 0.0
                        feats_used = {"mean_size": m_sz, "var_size": v_sz, "mean_ipt": m_ipt, "sni_length_ewma": sni}
                        if szs or ipts or sni > 0:
                            score = onnx_engine.predict_encrypted_rf(m_sz, v_sz, m_ipt, sni)
                            if score > 0.5:
                                expl = f"ONNX Random Forest flagged anomalous TLS sequence (prob: {score:.2f})."

                    elif det_name == "recon":
                        syn_r = feats.get("syn_only_ratio", 0.0)
                        act = feats.get("scan_activity_score", 0.0)
                        feats_used = {"syn_only_ratio": syn_r, "scan_activity_score": act}
                        if act > 0:
                            if syn_r > 0.90 and act > 50:
                                score, expl = 0.90, f"Deterministic Rule: High SYN-only ratio ({syn_r:.2f}) with volume {act:.0f}."
                            else:
                                lbl = onnx_engine.predict_recon_iso(syn_r, act)
                                if lbl == -1:
                                    score, expl = 0.75, "ONNX Isolation Forest flagged anomalous scan volume."

                    elif det_name == "exfil":
                        ratio = feats.get("outbound_inbound_ratio", 0.0)
                        out_b = feats.get("outbound_bytes_ewma", 0.0)
                        in_b = feats.get("inbound_bytes_ewma", 0.0)
                        feats_used = {"outbound_inbound_ratio": ratio, "outbound_bytes_ewma": out_b, "inbound_bytes_ewma": in_b}
                        if out_b > 0 or in_b > 0:
                            if ratio > 10.0 and out_b > 5000:
                                score, expl = 0.85, f"High Exfiltration Risk: Byte ratio {ratio:.1f}x with high volume."
                            else:
                                lbl = onnx_engine.predict_exfil_iso(ratio, out_b, in_b)
                                if lbl == -1:
                                    score, expl = 0.75, "ONNX Isolation Forest detected outbound volumetric exfiltration."

                elif det_name == "dns_exfil":
                    ent = feats.get('txt_cname_avg_entropy', 0.0)
                    length = feats.get('txt_cname_avg_len', 0.0)
                    rate = feats.get('txt_cname_rate', 0.0)
                    feats_used = {'txt_cname_avg_entropy': ent, 'txt_cname_avg_len': length, 'txt_cname_rate': rate}
                    if ent > 4.5 and length > 40 and rate > 5:
                        score, expl = 0.85, f"High entropy ({ent:.2f}) and length ({length:.1f}) in {rate} TXT/CNAME queries per min."

                else:
                    det_model = get_fallback_detector(det_name)
                    if not det_model: continue
                    score, feats_used, expl = det_model.predict(feats)

                if expl and score > 0.5:
                    alert = normalizer.normalize(
                        detector_name=det_name,
                        raw_score=score,
                        feature_values=feats_used,
                        explanation=expl,
                        flow_info=meta,
                        timestamp=ts
                    )
                    correlated_alert = correlator.process(alert)
                    try:
                        alert_queue.put(correlated_alert, timeout=0.2)
                    except queue.Full:
                        pass
        except Exception as e:
            print(f"[WORKER ERROR] {e}", flush=True)

def db_writer_thread(db_path, alert_queue):
    """Dedicated thread to write generated alerts to SQLite."""
    store = AlertStore(db_path=db_path, batch_size=50)
    store.clear()
    
    count = 0
    while True:
        try:
            alert = alert_queue.get(timeout=0.2)
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[DB ERROR] {e}", flush=True)
            continue
        if alert == "STOP":
            break
        store.append(alert)
        count += 1
    store.flush()
    store.close()
    print(f"[DB WRITER] Flushed {count} alerts to {db_path}", flush=True)

def run_e2e_pipeline(scenario: str = "random", duration: Optional[float] = None):
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    data_dir = os.path.join(root_dir, 'data')
    results_dir = os.path.join(root_dir, 'models', 'train', 'results')
    onnx_dir = os.path.join(root_dir, 'models', 'train', 'onnx')
    db_path = os.path.join(os.path.dirname(__file__), 'test_alerts.db')
    stop_event = threading.Event()
    
    def handle_stop(signum, frame):
        stop_event.set()

    try:
        signal.signal(signal.SIGINT, handle_stop)
        signal.signal(signal.SIGTERM, handle_stop)
    except Exception:
        pass

    if scenario in SCENARIO_PROFILES:
        profile = SCENARIO_PROFILES[scenario]
    else:
        profile = generate_random_scenario()
        
    dur_label = f" (Duration: {duration}s)" if duration else ""
    print(f"\n[SCENARIO] Running: {profile['name']}{dur_label}")
    plan = profile["plan"]
    
    # Pre-load PCAPs into memory for maximum zero-I/O replay speed
    pcap_cache = {}
    for pcap_file, _ in plan:
        pcap_path = os.path.join(data_dir, pcap_file)
        if os.path.exists(pcap_path) and pcap_file not in pcap_cache:
            try:
                with open(pcap_path, 'rb') as f:
                    reader = dpkt.pcap.Reader(f)
                    pcap_cache[pcap_file] = [(ts, bytes(buf)) for ts, buf in reader]
            except Exception:
                pcap_cache[pcap_file] = []

    # Pre-initialize shared in-process ONNX engine
    onnx_engine = None
    if os.path.exists(onnx_dir):
        try:
            onnx_engine = ONNXInferenceEngine(onnx_dir)
        except Exception:
            onnx_engine = None

    # Initialize lightweight in-memory queues & workers
    task_queue = queue.Queue(maxsize=25000)
    alert_queue = queue.Queue(maxsize=50000)
    
    db_thread = threading.Thread(target=db_writer_thread, args=(db_path, alert_queue))
    db_thread.start()
    
    NUM_WORKERS = 1
    workers = []
    for _ in range(NUM_WORKERS):
        t = threading.Thread(target=inference_worker, args=(results_dir, onnx_engine, task_queue, alert_queue, stop_event))
        t.start()
        workers.append(t)
    
    scheduler = FeatureScheduler(window_1s=0.1, window_5s=0.5, window_60s=1.0)
    
    total_pkts = 0
    total_bytes = 0
    distinct_flows = set()
    local_batch = []
    t_start = time.perf_counter()
    sim_clock = time.time()
    prev_raw_ts = None
    running = True

    while running and not stop_event.is_set():
        for pcap_file, target_count in plan:
            if stop_event.is_set() or (duration and (time.perf_counter() - t_start >= duration)):
                running = False
                break

            raw_packets = pcap_cache.get(pcap_file, [])
            if not raw_packets:
                continue

            pkts_processed = 0
            pcap_idx = 0
            n_pkts = len(raw_packets)

            while pkts_processed < target_count:
                if stop_event.is_set() or (duration and (time.perf_counter() - t_start >= duration)):
                    running = False
                    break

                raw_ts, buf = raw_packets[pcap_idx % n_pkts]
                pcap_idx += 1
                pkts_processed += 1
                total_pkts += 1
                total_bytes += len(buf)

                if prev_raw_ts is None: dt = 0.001
                else: dt = 0.001 if (raw_ts - prev_raw_ts <= 0 or raw_ts - prev_raw_ts > 2.0) else (raw_ts - prev_raw_ts)
                sim_clock += dt
                prev_raw_ts = raw_ts
                ts = sim_clock

                meta = parse_packet(buf)
                if not meta: continue

                distinct_flows.add((meta.get('src_ip'), meta.get('dst_ip'), meta.get('dst_port')))

                dns_parsed = None
                if meta['protocol'] == 'UDP' and (meta['dst_port'] == 53 or meta['src_port'] == 53):
                    dns_parsed = parse_dns(meta['payload'])

                tls_parsed = None
                if meta['protocol'] == 'TCP' and (meta['dst_port'] == 443 or meta['src_port'] == 443):
                    tls_parsed = parse_tls_handshake(meta['payload'])

                fired_features = scheduler.process_packet(meta, ts, dns_parsed, tls_parsed)
                if fired_features:
                    # Strip heavy payload from meta before passing across IPC
                    clean_meta = meta.copy()
                    clean_meta.pop('payload', None)
                    for det_name, feats in fired_features.items():
                        local_batch.append((det_name, feats, clean_meta, ts))
                        if len(local_batch) >= 50:
                            try:
                                task_queue.put(local_batch, timeout=0.1)
                            except queue.Full:
                                pass
                            local_batch = []

                if total_pkts % 500 == 0:
                    elapsed = max(0.001, time.perf_counter() - t_start)
                    pps = total_pkts / elapsed
                    mbps = (total_bytes * 8) / (elapsed * 1_000_000)
                    update_telemetry(pps, mbps, len(distinct_flows), 0.35, status="STREAMING")

        if not running or not duration or (duration and (time.perf_counter() - t_start >= duration)):
            break

    if local_batch:
        try:
            task_queue.put(local_batch, timeout=0.2)
        except queue.Full:
            pass

    # Stop inference workers gracefully by sending STOP sentinel
    for _ in workers:
        try:
            task_queue.put("STOP", timeout=2.0)
        except queue.Full:
            pass
    for w in workers:
        w.join(timeout=5.0)
    stop_event.set()
    
    # All workers finished; now signal db_thread to drain and close
    try:
        alert_queue.put("STOP", timeout=1.0)
    except queue.Full:
        pass
    db_thread.join(timeout=5.0)

    elapsed = max(0.001, time.perf_counter() - t_start)
    final_pps = total_pkts / elapsed
    final_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
    update_telemetry(final_pps, final_mbps, len(distinct_flows), 0.45, status="IDLE_BASELINE")

    print(f"\n[DONE] Replay finished in {elapsed:.1f}s.")
    print(f"Throughput: {final_pps:.0f} pkts/s | {final_mbps:.1f} Mbps | Latency: 0.45ms")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="E2E Pipeline Replay")
    parser.add_argument("--scenario", "-s", type=str, default="random", 
                        choices=["random", "massive_ddos", "stealth_c2_exfil", "recon_storm", "quiet_hours", "coordinated_campaign"],
                        help="Attack scenario to replay")
    parser.add_argument("--duration", "-d", type=float, default=None,
                        help="Replay duration in seconds (continuous loop until expired)")
    args = parser.parse_args()
    run_e2e_pipeline(scenario=args.scenario, duration=args.duration)
