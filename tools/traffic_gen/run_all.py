import subprocess
import os
import sys

def main():
    scripts_to_run = [
        "benign_traffic_gen.py",
        "c2_beacon_gen.py",
        "dns_tunnel_gen.py",
        "port_scan_gen.py",
        "syn_flood_gen.py",
        "udp_amplification_gen.py"
    ]
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    for script in scripts_to_run:
        script_path = os.path.join(script_dir, script)
        print(f"Running {script}...")
        try:
            # Run with the same Python executable
            subprocess.run([sys.executable, script_path], check=True)
            print(f"Successfully finished {script}\n")
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while running {script}: {e}\n", file=sys.stderr)
        except FileNotFoundError:
            print(f"Could not find {script} at {script_path}\n", file=sys.stderr)

if __name__ == "__main__":
    main()
