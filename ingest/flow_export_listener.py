import socket
import logging

logger = logging.getLogger(__name__)

class UnidirectionalFlowListener:
    """
    A UDP listener for NetFlow v9 / IPFIX / sFlow.
    Structurally enforces a unidirectional constraint: there is no code path
    to send responses, acks, or ICMP replies.
    """
    def __init__(self, host='0.0.0.0', port=2055, buffer_size=65535):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.sock = None
        
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind to receive data
        self.sock.bind((self.host, self.port))
        logger.info(f"Listening for flow records on UDP {self.host}:{self.port}")
        
    def listen_loop(self, callback):
        """
        Listens indefinitely. Calls `callback(data, addr)` for each datagram.
        """
        if not self.sock:
            raise RuntimeError("Listener not started")
            
        try:
            while True:
                data, addr = self.sock.recvfrom(self.buffer_size)
                # CONSTRAINT CHECK: We only ever read. 
                # There is strictly no self.sock.send() or self.sock.sendto()
                # in this class.
                callback(data, addr)
        except KeyboardInterrupt:
            logger.info("Stopping flow listener.")
        except Exception as e:
            logger.error(f"Error in listener: {e}")
        finally:
            self.stop()
            
    def stop(self):
        if self.sock:
            self.sock.close()
            self.sock = None

def dummy_callback(data, addr):
    # Basic skeleton parser hook. Deep parsing left for feature extraction phase.
    print(f"Received {len(data)} bytes from {addr}. (Parse hook)")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    listener = UnidirectionalFlowListener(port=9999)
    listener.start()
    print("Press Ctrl+C to stop.")
    listener.listen_loop(dummy_callback)
