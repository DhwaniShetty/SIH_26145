import os
import sys

# Add project root to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from parsers.tls_quic_handshake import parse_tls_handshake

def test_no_payload_leak():
    # Construct a dummy TLS stream. 
    # Record Type 22 (Handshake), Version 03 01, Length 00 04, Handshake Type 1 (ClientHello), Length 00 00 00
    handshake_record = b'\x16\x03\x01\x00\x04\x01\x00\x00\x00'
    
    # Record Type 23 (Application Data), Version 03 01, Length 00 13
    secret_payload = b'TOP_SECRET_PAYLOAD_'
    app_data_record = b'\x17\x03\x01\x00\x13' + secret_payload
    
    combined_stream = handshake_record + app_data_record
    
    result = parse_tls_handshake(combined_stream)
    
    # Convert result to string to check for leaks
    result_str = str(result)
    
    assert result is not None
    assert "TOP_SECRET" not in result_str, "Payload leak detected! Application data was parsed and retained."
    print("test_no_payload_leak passed.")

if __name__ == "__main__":
    test_no_payload_leak()
