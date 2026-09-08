import dpkt
import socket

def inet_to_str(inet):
    """Convert inet object to a string"""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def parse_packet(raw_buf):
    """
    Parses Ethernet, IP, and TCP/UDP headers using dpkt.
    Returns a dictionary of extracted metadata or None if parsing fails.
    This operates on raw byte buffers without creating heavy python objects.
    """
    try:
        if raw_buf[0] >> 4 == 4:
            ip = dpkt.ip.IP(raw_buf)
        elif raw_buf[0] >> 4 == 6:
            ip = dpkt.ip6.IP6(raw_buf)
        else:
            eth = dpkt.ethernet.Ethernet(raw_buf)
            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return None
            ip = eth.data
    except Exception:
        return None
    src_ip = inet_to_str(ip.src)
    dst_ip = inet_to_str(ip.dst)
    
    meta = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_len": ip.len if isinstance(ip, dpkt.ip.IP) else 0, # IP6 doesn't have .len
        "protocol": None,
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": 0,
        "payload": b""
    }

    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        meta["protocol"] = "TCP"
        meta["src_port"] = tcp.sport
        meta["dst_port"] = tcp.dport
        meta["tcp_flags"] = tcp.flags
        meta["payload"] = tcp.data
    elif isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        meta["protocol"] = "UDP"
        meta["src_port"] = udp.sport
        meta["dst_port"] = udp.dport
        meta["payload"] = udp.data
    elif isinstance(ip.data, dpkt.icmp.ICMP):
        meta["protocol"] = "ICMP"
        meta["payload"] = ip.data.data
        
    return meta
