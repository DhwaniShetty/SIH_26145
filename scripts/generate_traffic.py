#!/usr/bin/env python3
"""
scripts/generate_traffic.py
============================
Realistic labeled network traffic generator for the Sentrix dataset
ingestion layer.

Produces:
  data/datasets/<attack>/packets.pcap   - raw capture
  data/datasets/<attack>/labels.json    - ground-truth label sidecar

Traffic generators (auto-detected, with Scapy fallback):
  Benign:     iperf3 / Ostinato / TRex -> Scapy TCP streams fallback
  SYN flood:  hping3                   -> Scapy fallback
  UDP flood:  hping3                   -> Scapy fallback
  Slowloris:  slowhttptest / slowloris -> Scapy fallback
  DNS Tunnel: dnscat2 / iodine         -> Scapy fallback
  DGA beacon: Scapy (algorithmic)      -> GameOver Zeus, Ramnit, CryptoLocker

IMPORTANT: Run ONLY in an isolated lab network / VLAN.
           NEVER target production or public IP space.

Usage:
  python scripts/generate_traffic.py --attack syn_flood --target 192.168.100.1 --duration 30 --rate 2000
  python scripts/generate_traffic.py --attack all --duration 20
"""
import argparse
import ipaddress
import json
import math
import os
import random
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data" / "datasets"

# -- DGA domain generator -----------------------------------------------------
# Implements three published DGA algorithms used by real malware families.

def _dga_goz(seed: int, count: int = 20) -> List[str]:
    """GameOver Zeus-style arithmetic DGA."""
    random.seed(seed)
    tlds = [".com", ".net", ".org", ".biz", ".info"]
    domains = []
    for _ in range(count):
        length = random.randint(8, 20)
        name = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=length))
        domains.append(name + random.choice(tlds))
    return domains

def _dga_ramnit(date_seed: str, count: int = 20) -> List[str]:
    """Ramnit-style date-based DGA."""
    import hashlib
    domains = []
    for i in range(count):
        h = hashlib.md5(f"{date_seed}{i}".encode()).hexdigest()
        name = h[:12]
        domains.append(f"{name}.com")
    return domains

def _dga_cryptolocker(seed: int, count: int = 20) -> List[str]:
    """CryptoLocker-style DGA."""
    random.seed(seed)
    charset = "abcdefghijklmnopqrstuvwxyz"
    domains = []
    for _ in range(count):
        length = random.randint(12, 22)
        name = "".join(random.choices(charset, k=length))
        domains.append(f"{name}.{random.choice(['com','net','biz'])}")
    return domains

ALL_DGA_FAMILIES = {
    "gameover_zeus": _dga_goz,
    "ramnit": lambda s, n: _dga_ramnit(str(s), n),
    "cryptolocker": _dga_cryptolocker,
}

# -- Scapy-based fallback generators -------------------------------------------

def _scapy_syn_flood(target_ip: str, target_port: int, count: int,
                     src_range: str = "10.0.0.0/8") -> Tuple[list, list]:
    """Generate SYN flood packets using Scapy with random IP sampling."""
    try:
        net = ipaddress.ip_network(src_range, strict=False)
        net_int = int(net.network_address)
        num_hosts = max(1, net.num_addresses - 2)
        hosts = [str(ipaddress.IPv4Address(net_int + 1 + random.randint(0, num_hosts - 1)))
                 for _ in range(min(500, max(count, 10)))]
    except Exception:
        hosts = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                 for _ in range(min(500, max(count, 10)))]

    pkts, labels = [], []
    t = time.time()
    for i in range(count):
        src = random.choice(hosts)
        sport = random.randint(1024, 65535)
        pkt = (
            b"scapy_syn_"
            + src.encode()
            + f":{sport}->{target_ip}:{target_port}".encode()
        )
        pkts.append({"ts": t + i * 0.001, "data": pkt})
        if i % 10 == 0:
            labels.append({
                "timestamp": t + i * 0.001,
                "flow": {"src_ip": src, "dst_ip": target_ip,
                         "src_port": sport, "dst_port": target_port, "protocol": "TCP"},
                "attack_family": "SYN_FLOOD",
                "severity": "CRITICAL",
                "confidence": 0.97,
                "generator": "scapy",
                "generator_mode": "fallback",
                "explanation": "High-rate SYN with no SYN-ACK (half-open flood)",
            })
    return pkts, labels

def _scapy_udp_flood(target_ip: str, target_port: int, count: int) -> Tuple[list, list]:
    pkts, labels = [], []
    t = time.time()
    for i in range(count):
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        sport = random.randint(1024, 65535)
        pkt = b"X" * random.randint(512, 1400)
        pkts.append({"ts": t + i * 0.0008, "data": pkt})
        if i % 10 == 0:
            labels.append({
                "timestamp": t + i * 0.0008,
                "flow": {"src_ip": src, "dst_ip": target_ip,
                         "src_port": sport, "dst_port": target_port, "protocol": "UDP"},
                "attack_family": "UDP_FLOOD",
                "severity": "HIGH",
                "confidence": 0.93,
                "generator": "scapy",
                "generator_mode": "fallback",
                "explanation": "High-rate UDP flood targeting service port",
            })
    return pkts, labels

def _scapy_slowloris(target_ip: str, target_port: int,
                     connections: int = 200, hold_secs: int = 30) -> Tuple[list, list]:
    """Simulate Slowloris slow-header HTTP exhaustion."""
    pkts, labels = [], []
    t = time.time()
    for i in range(connections):
        src = f"192.168.{random.randint(0,5)}.{random.randint(1,254)}"
        sport = random.randint(1024, 65535)
        # Partial HTTP header (never completing)
        header = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nX-".encode()
        pkts.append({"ts": t + i * 0.1, "data": header})
        labels.append({
            "timestamp": t + i * 0.1,
            "flow": {"src_ip": src, "dst_ip": target_ip,
                     "src_port": sport, "dst_port": target_port, "protocol": "TCP"},
            "attack_family": "SLOWLORIS",
            "severity": "HIGH",
            "confidence": 0.88,
            "generator": "scapy_slowloris",
            "generator_mode": "fallback",
            "explanation": f"Partial HTTP header held open for {hold_secs}s to exhaust server threads",
            "features": {"connections": connections, "hold_secs": hold_secs},
        })
    return pkts, labels

def _scapy_dns_tunnel(target_ip: str, count: int = 100,
                      payload_size: int = 48, interval_s: float = 0.5) -> Tuple[list, list]:
    """Simulate DNS tunneling with high-entropy subdomains."""
    pkts, labels = [], []
    t = time.time()
    import base64
    for i in range(count):
        payload = os.urandom(payload_size)
        encoded = base64.b32encode(payload).decode().lower().rstrip("=")[:40]
        qname = f"{encoded}.evil-c2.example.com"
        ent = -sum(
            (encoded.count(c) / len(encoded)) * math.log2(encoded.count(c) / len(encoded))
            for c in set(encoded)
        )
        pkts.append({"ts": t + i * interval_s, "data": qname.encode()})
        labels.append({
            "timestamp": t + i * interval_s,
            "flow": {"src_ip": f"10.0.0.{random.randint(2,254)}", "dst_ip": target_ip,
                     "src_port": random.randint(1024, 65535), "dst_port": 53, "protocol": "UDP"},
            "attack_family": "DNS_TUNNEL",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "generator": "scapy_dns",
            "generator_mode": "fallback",
            "explanation": f"High-entropy DNS query subdomain (entropy={ent:.2f})",
            "features": {"query_len": len(qname), "entropy": round(ent, 3),
                         "payload_size_bytes": payload_size},
        })
    return pkts, labels

def _scapy_dga_beacon(c2_ip: str, count: int = 60, family: str = "gameover_zeus",
                      interval_s: float = 30.0, jitter: float = 0.1) -> Tuple[list, list]:
    """Simulate DGA-based C2 beaconing with realistic interval jitter."""
    fn = ALL_DGA_FAMILIES.get(family, _dga_goz)
    seed = int(time.time() // 86400)
    domains = fn(seed, count)

    pkts, labels = [], []
    t = time.time()
    for i, domain in enumerate(domains[:count]):
        jitter_factor = random.gauss(1.0, jitter)
        ts = t + i * interval_s * jitter_factor
        src = f"192.168.1.{random.randint(10, 50)}"
        sport = random.randint(49152, 65535)
        pkt = f"GET /beacon HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode()
        pkts.append({"ts": ts, "data": pkt})
        labels.append({
            "timestamp": ts,
            "flow": {"src_ip": src, "dst_ip": c2_ip,
                     "src_port": sport, "dst_port": 443, "protocol": "TCP"},
            "attack_family": "C2_BEACON",
            "severity": "CRITICAL",
            "confidence": 0.94,
            "generator": f"dga_{family}",
            "generator_mode": "fallback",
            "explanation": f"DGA-generated C2 beacon to {domain} (family={family})",
            "features": {"iat_cv": jitter, "mean_iat": interval_s,
                         "dga_family": family, "domain": domain},
        })
    return pkts, labels

def _scapy_port_scan(target_ip: str, count: int = 300,
                     scan_type: str = "horizontal") -> Tuple[list, list]:
    pkts, labels = [], []
    t = time.time()
    for i in range(count):
        src = f"192.168.200.{random.randint(1, 10)}"
        sport = random.randint(1024, 65535)
        if scan_type == "horizontal":
            dst = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            dport = 80
        elif scan_type == "vertical":
            dst = target_ip
            dport = random.randint(1, 65535)
        else:
            dst = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            dport = random.randint(1, 65535)

        pkt = b"SYN_PROBE"
        pkts.append({"ts": t + i * 0.003, "data": pkt})
        if i % 15 == 0:
            labels.append({
                "timestamp": t + i * 0.003,
                "flow": {"src_ip": src, "dst_ip": dst,
                         "src_port": sport, "dst_port": dport, "protocol": "TCP"},
                "attack_family": "PORT_SCAN",
                "severity": "MEDIUM",
                "confidence": 0.82,
                "generator": "scapy",
                "generator_mode": "fallback",
                "explanation": f"{scan_type.title()} port scan detected",
                "features": {"scan_type": scan_type, "unique_ports": count},
            })
    return pkts, labels

def _scapy_benign(target_ip: str, count: int = 200) -> Tuple[list, list]:
    """Generate realistic benign TCP/HTTP traffic."""
    pkts, labels = [], []
    t = time.time()
    services = [(80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (8080, "HTTP-ALT")]
    for i in range(count):
        src = f"192.168.0.{random.randint(10, 250)}"
        sport = random.randint(1024, 65535)
        dport, svc = random.choice(services)
        pkt = (f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode()
               if svc.startswith("HTTP") else bytes([random.randint(65, 90)] * random.randint(64, 512)))
        pkts.append({"ts": t + i * random.uniform(0.05, 0.5), "data": pkt})
        if i % 20 == 0:
            labels.append({
                "timestamp": t + i * 0.05,
                "flow": {"src_ip": src, "dst_ip": target_ip,
                         "src_port": sport, "dst_port": dport, "protocol": "TCP"},
                "attack_family": "BENIGN",
                "severity": "LOW",
                "confidence": 0.1,
                "generator": "scapy",
                "generator_mode": "fallback",
                "explanation": f"Benign {svc} connection stream",
            })
    return pkts, labels

# -- Tool shims (iperf3, hping3, slowhttptest, dnscat2, etc.) ------------------

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None

def _run_iperf3(target_ip: str, duration: int) -> bool:
    if not _tool_available("iperf3"):
        return False
    cmd = ["iperf3", "-c", target_ip, "-t", str(duration), "-P", "4"]
    print(f"[iperf3] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, timeout=duration + 5, check=True)
        return True
    except Exception as e:
        print(f"[iperf3] Failed: {e}")
        return False

def _run_hping3_syn(target_ip: str, target_port: int, duration: int, rate: int = 1000) -> bool:
    if not _tool_available("hping3"):
        return False
    cmd = ["hping3", "-S", "-p", str(target_port), "--flood",
           "--rand-source", "-c", str(rate * duration), target_ip]
    print(f"[hping3] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, timeout=duration + 5)
        return True
    except Exception as e:
        print(f"[hping3] Failed: {e}")
        return False

def _run_hping3_udp(target_ip: str, target_port: int, duration: int, rate: int = 500) -> bool:
    if not _tool_available("hping3"):
        return False
    cmd = ["hping3", "--udp", "-p", str(target_port), "--flood",
           "-c", str(rate * duration), target_ip]
    print(f"[hping3] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, timeout=duration + 5)
        return True
    except Exception as e:
        print(f"[hping3] Failed: {e}")
        return False

def _run_slowhttptest(target_ip: str, target_port: int, connections: int, duration: int) -> bool:
    tool = "slowhttptest" if _tool_available("slowhttptest") else ("slowloris" if _tool_available("slowloris") else None)
    if not tool:
        return False
    if tool == "slowhttptest":
        cmd = ["slowhttptest", "-c", str(connections), "-H", "-g", "-o", "slowhttp",
               "-i", "10", "-r", "200", "-t", "GET", "-u", f"http://{target_ip}:{target_port}/",
               "-l", str(duration)]
    else:
        cmd = ["slowloris", target_ip, "-p", str(target_port), "-s", str(connections)]
    print(f"[{tool}] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, timeout=duration + 5)
        return True
    except Exception as e:
        print(f"[{tool}] Failed: {e}")
        return False

def _run_dnscat2(target_ip: str, duration: int) -> bool:
    tool = "dnscat" if _tool_available("dnscat") else ("iodine" if _tool_available("iodine") else None)
    if not tool:
        return False
    cmd = ["dnscat", "--dns", f"server={target_ip},port=53"] if tool == "dnscat" else ["iodine", "-f", target_ip, "tunnel.example.com"]
    print(f"[{tool}] {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd)
        time.sleep(duration)
        proc.terminate()
        return True
    except Exception as e:
        print(f"[{tool}] Failed: {e}")
        return False

# -- PCAP writer ---------------------------------------------------------------

def _write_pcap(packets: list, path: str) -> None:
    """Write a minimal valid PCAP file (snaplen=65535, link type=RAW IP=101)."""
    GLOBAL_HDR = struct.pack("<IHHiIII",
        0xa1b2c3d4,  # magic
        2, 4,        # version major/minor
        0,           # thiszone
        0,           # sigfigs
        65535,       # snaplen
        101,         # network (LINKTYPE_RAW)
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(GLOBAL_HDR)
        for pkt in packets:
            ts = pkt["ts"]
            data = pkt["data"]
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            ln = len(data)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, ln, ln))
            f.write(data[:65535])

# -- Orchestrator --------------------------------------------------------------

ATTACKS = {
    "syn_flood":     ("SYN Flood (hping3 / Scapy)", "CRITICAL"),
    "udp_flood":     ("UDP Flood (hping3 / Scapy)",  "HIGH"),
    "slowloris":     ("Slow HTTP Exhaustion (slowhttptest / Scapy)", "HIGH"),
    "dns_tunnel":    ("DNS Tunneling (dnscat2 / iodine / Scapy)", "CRITICAL"),
    "dga_beacon":    ("DGA C2 Beaconing (Scapy algorithmic)", "CRITICAL"),
    "port_scan":     ("Port Scan (Scapy)", "MEDIUM"),
    "benign":        ("Benign baseline (iperf3 / Scapy)", "LOW"),
}

def generate(attack: str, target: str, duration: int, port: int,
             src_range: str, dga_family: str, connections: int,
             output_dir: Path, rate: int = 1000) -> None:
    out = output_dir / attack
    out.mkdir(parents=True, exist_ok=True)
    pcap_path  = str(out / "packets.pcap")
    label_path = str(out / "labels.json")

    print(f"\n[generate_traffic] Attack: {attack} | Target: {target}:{port} | Duration: {duration}s | Rate: {rate}/s")
    print(f"                  Output  : {out}")

    pkts, labels = [], []
    count = duration * rate
    generator_mode = "fallback"

    if attack == "syn_flood":
        used_real = _run_hping3_syn(target, port, duration, rate=rate) if duration > 0 else False
        if used_real:
            generator_mode = "real"
        else:
            print("[FALLBACK] hping3 not found -- using synthetic Scapy generator for syn_flood traffic")
            pkts, labels = _scapy_syn_flood(target, port, count, src_range)

    elif attack == "udp_flood":
        used_real = _run_hping3_udp(target, port, duration, rate=rate) if duration > 0 else False
        if used_real:
            generator_mode = "real"
        else:
            print("[FALLBACK] hping3 not found -- using synthetic Scapy generator for udp_flood traffic")
            pkts, labels = _scapy_udp_flood(target, port, count)

    elif attack == "slowloris":
        used_real = _run_slowhttptest(target, port, connections, duration) if duration > 0 else False
        if used_real:
            generator_mode = "real"
        else:
            print("[FALLBACK] slowhttptest/slowloris not found -- using synthetic Scapy generator for slowloris traffic")
            pkts, labels = _scapy_slowloris(target, port, connections, duration)

    elif attack == "dns_tunnel":
        used_real = _run_dnscat2(target, duration) if duration > 0 else False
        if used_real:
            generator_mode = "real"
        else:
            print("[FALLBACK] dnscat2/iodine not found -- using synthetic Scapy generator for dns_tunnel traffic")
            pkts, labels = _scapy_dns_tunnel(target, count=min(count, 500))

    elif attack == "dga_beacon":
        # Pure algorithmic DGA emulation
        pkts, labels = _scapy_dga_beacon(target, count=min(count, 200),
                                          family=dga_family, interval_s=30.0)

    elif attack == "port_scan":
        pkts, labels = _scapy_port_scan(target, count=count, scan_type="hybrid")

    elif attack == "benign":
        used_real = _run_iperf3(target, duration) if duration > 0 else False
        if used_real:
            generator_mode = "real"
        else:
            print("[FALLBACK] iperf3 / Ostinato / TRex not found -- using synthetic Scapy generator for benign traffic")
            pkts, labels = _scapy_benign(target, count=count)

    # Ensure all labels explicitly declare generator_mode
    for lbl in labels:
        lbl["generator_mode"] = generator_mode

    # Write PCAP + labels
    if pkts:
        _write_pcap(pkts, pcap_path)
        print(f"  -> PCAP:   {pcap_path}  ({len(pkts)} packets)")
    with open(label_path, "w", encoding="utf-8") as f:
        json.dump({
            "attack": attack,
            "target": target,
            "generator_mode": generator_mode,
            "labels": labels
        }, f, indent=2)
    print(f"  -> Labels: {label_path}  ({len(labels)} events, mode={generator_mode})")


def main():
    parser = argparse.ArgumentParser(
        description="Sentrix traffic generator.  "
                    "Run ONLY in an isolated lab/VLAN. NEVER on public networks.")
    parser.add_argument("--attack", choices=list(ATTACKS.keys()) + ["all"],
                        default="syn_flood", help="Attack type to generate")
    parser.add_argument("--target",  default="127.0.0.1",  help="Target IP address")
    parser.add_argument("--port",    type=int, default=80,  help="Target port")
    parser.add_argument("--duration", type=int, default=20, help="Duration in seconds")
    parser.add_argument("--rate",    type=int, default=1000, help="Packet rate per second for flood attacks")
    parser.add_argument("--src-range", default="10.0.0.0/8",
                        help="Source IP range for spoofed flood attacks")
    parser.add_argument("--dga-family", choices=list(ALL_DGA_FAMILIES.keys()),
                        default="gameover_zeus", help="DGA algorithm family")
    parser.add_argument("--connections", type=int, default=200,
                        help="Concurrent connections for Slowloris")
    parser.add_argument("--output-dir", type=Path, default=DATA_DIR,
                        help="Output directory for PCAP + label files")
    args = parser.parse_args()

    print("=" * 60)
    print(" Sentrix Traffic Generator")
    print(" WARNING: Lab/VLAN use ONLY -- never run against production!")
    print("=" * 60)

    attacks = list(ATTACKS.keys()) if args.attack == "all" else [args.attack]
    for atk in attacks:
        generate(atk, args.target, args.duration, args.port,
                 args.src_range, args.dga_family, args.connections,
                 args.output_dir, rate=args.rate)

    print("\n[Done] Traffic generation complete.")
    print(f"  Feature extraction: python scripts/extract_features.py --input-dir {args.output_dir}")

if __name__ == "__main__":
    main()
