import dpkt
import queue
import logging
import threading
import time

logger = logging.getLogger(__name__)

class BoundedPcapReader:
    """
    Reads packets from a PCAP file and feeds them into a bounded ring buffer (queue).
    If the buffer nears capacity, it falls back to sampling (dropping packets) to avoid 
    blocking the upstream tap or causing OOM.
    """
    def __init__(self, pcap_path, max_buffer_size=10000, sample_rate_on_pressure=0.1):
        self.pcap_path = pcap_path
        self.max_buffer_size = max_buffer_size
        self.buffer = queue.Queue(maxsize=max_buffer_size)
        self.sample_rate_on_pressure = sample_rate_on_pressure
        self._stop_event = threading.Event()
        self._producer_thread = None
        self.dropped_packets = 0

    def start(self):
        self._producer_thread = threading.Thread(target=self._ingest_loop, daemon=True)
        self._producer_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._producer_thread:
            self._producer_thread.join()

    def _ingest_loop(self):
        try:
            with open(self.pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                packet_count = 0
                for ts, buf in pcap:
                    if self._stop_event.is_set():
                        break
                    
                    packet_count += 1
                    
                    # Pressure threshold: 80% full
                    if self.buffer.qsize() > self.max_buffer_size * 0.8:
                        # Fallback to sampling to avoid blocking
                        # If sample_rate is 0.1, we keep 1 in 10 packets
                        if packet_count % int(1.0 / self.sample_rate_on_pressure) != 0:
                            self.dropped_packets += 1
                            continue
                            
                    try:
                        self.buffer.put_nowait((ts, buf))
                    except queue.Full:
                        # Hard drop if queue is completely full despite sampling
                        self.dropped_packets += 1
                        
        except Exception as e:
            logger.error(f"Error reading pcap: {e}")
            
        # Put a sentinel value to indicate EOF
        try:
            self.buffer.put((None, None), timeout=1)
        except queue.Full:
            pass

    def get_packet(self, timeout=0.005):
        """
        Retrieves a packet from the buffer.
        Returns (ts, buf) or (None, None) if EOF, or raises queue.Empty on timeout.
        """
        return self.buffer.get(timeout=timeout)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import sys
    if len(sys.argv) > 1:
        reader = BoundedPcapReader(sys.argv[1], max_buffer_size=100)
        reader.start()
        
        count = 0
        while True:
            try:
                ts, buf = reader.get_packet()
                if ts is None:
                    break
                count += 1
                # Simulate slow processing to trigger sampling
                if count % 10 == 0:
                    time.sleep(0.01) 
            except queue.Empty:
                continue
                
        reader.stop()
        print(f"Processed {count} packets. Dropped {reader.dropped_packets} packets due to buffer pressure.")
