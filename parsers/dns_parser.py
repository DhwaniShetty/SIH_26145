import dpkt
import logging

logger = logging.getLogger(__name__)

def parse_dns(udp_payload):
    """
    Parses a UDP payload as DNS. 
    Returns a list of queried names, their types, and TTLs (if present in answers).
    """
    if not udp_payload:
        return None
        
    try:
        dns = dpkt.dns.DNS(udp_payload)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, UnicodeDecodeError):
        # Not a valid DNS payload or truncated
        return None
        
    result = {
        "queries": [],
        "answers": []
    }
    
    for q in dns.qd:
        result["queries"].append({
            "name": q.name,
            "type": q.type
        })
        
    for a in dns.an:
        # dpkt.dns.DNS.RR
        if hasattr(a, 'name') and hasattr(a, 'type') and hasattr(a, 'ttl'):
            result["answers"].append({
                "name": a.name,
                "type": a.type,
                "ttl": a.ttl
            })
            
    return result
