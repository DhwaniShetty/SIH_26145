from collections import OrderedDict
import time
import logging

logger = logging.getLogger(__name__)

class BoundedTable:
    """
    An LRU-evicted bounded table with an optional TTL.
    Used for Flow tracking, DNS transactions, and TLS sessions.
    """
    def __init__(self, name, max_size=10000, ttl_seconds=300):
        self.name = name
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        # OrderedDict for O(1) LRU behavior
        self.table = OrderedDict()
        self.evicted_count = 0

    def _evict_lru(self):
        """Evict the oldest (first) item."""
        if self.table:
            self.table.popitem(last=False)
            self.evicted_count += 1

    def _evict_expired(self, current_time):
        """Evicts entries older than TTL."""
        keys_to_remove = []
        # OrderedDict iterates from oldest to newest
        for k, v in self.table.items():
            if current_time - v.get('last_seen', current_time) > self.ttl_seconds:
                keys_to_remove.append(k)
            else:
                # Since it's LRU, newer items are at the end, 
                # but last_seen isn't strictly monotonic with LRU if updated.
                # However, for performance we check all or just rely on LRU.
                pass
                
        for k in keys_to_remove:
            del self.table[k]
            self.evicted_count += 1

    def get_or_create(self, key, default_factory, current_time=None):
        if current_time is None:
            current_time = time.time()
            
        if key in self.table:
            # Move to end (most recently used)
            self.table.move_to_end(key)
            entry = self.table[key]
            entry['last_seen'] = current_time
            return entry
            
        # Create new
        if len(self.table) >= self.max_size:
            self._evict_lru()
            
        new_entry = default_factory()
        new_entry['first_seen'] = current_time
        new_entry['last_seen'] = current_time
        self.table[key] = new_entry
        return new_entry
        
    def get(self, key):
        if key in self.table:
            self.table.move_to_end(key)
            return self.table[key]
        return None

class FlowAssembler:
    """
    Maintains 5-tuple flow tables, DNS tables, and TLS tables.
    """
    def __init__(self, max_flows=10000, max_dns=5000, max_tls=5000):
        self.flows = BoundedTable("5-Tuple Flows", max_size=max_flows)
        self.dns_tx = BoundedTable("DNS Transactions", max_size=max_dns, ttl_seconds=10)
        self.tls_sessions = BoundedTable("TLS Sessions", max_size=max_tls)
        
    def _make_5tuple(self, meta):
        # Normalize direction for a flow key (e.g. smaller IP first)
        ip1, ip2 = sorted([meta['src_ip'], meta['dst_ip']])
        port1, port2 = sorted([meta['src_port'], meta['dst_port']])
        return (ip1, port1, ip2, port2, meta['protocol'])
        
    def process_packet_meta(self, meta, current_time=None):
        if not meta or not meta.get('protocol'):
            return None
            
        key = self._make_5tuple(meta)
        
        def flow_factory():
            return {
                "packet_count": 0,
                "byte_count": 0,
                "protocol": meta['protocol'],
                "src_ip": meta['src_ip'],
                "dst_ip": meta['dst_ip'],
                "src_port": meta['src_port'],
                "dst_port": meta['dst_port']
            }
            
        flow = self.flows.get_or_create(key, flow_factory, current_time)
        flow['packet_count'] += 1
        flow['byte_count'] += meta.get('ip_len', 0)
        
        return flow
