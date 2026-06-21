"""
trigger_test.py
----------------
A simple test traffic generator to validate your sniffer's
port-scan detection logic.

It opens quick TCP connection attempts to several ports on the
target in a short burst — enough to cross the
UNIQUE_PORTS_THRESHOLD (currently 3 ports / 10s) in your sniffer.

Usage:
    python3 trigger_test.py <target_ip> [num_ports]

Example:
    python trigger_test.py 192.168.1.101 10
"""

import socket
import sys
import time


def quick_connect(ip, port, timeout=0.3):
    """
    Attempt a fast TCP connect to a single port.
    We don't care whether it succeeds — even a refused
    connection (RST) still sends a SYN packet first, which
    is exactly what the sniffer is watching for.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect_ex((ip, port))
    except Exception as e:
        print(f"  (port {port} error, ignored: {e})")


def run_port_scan_simulation(ip, num_ports=10, delay=0.2):
    """
    Hit `num_ports` sequential ports on `ip` with a small delay
    between each — fast enough to land inside the sniffer's
    sliding time window (default 10s), slow enough that each
    SYN is a distinct packet rather than a flood.
    """

    # Pick a spread of common + uncommon ports so it looks like
    # real reconnaissance rather than one repeated port.
    base_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443,
                  445, 5900, 9999, 1234, 6667]
    ports = base_ports[:num_ports]

    print(f"🔬 Simulating port scan against {ip}")
    print(f"   Hitting {len(ports)} ports: {ports}")
    print(f"   (delay {delay}s between attempts)\n")

    start = time.time()

    for port in ports:
        print(f"  → connecting to {ip}:{port}")
        quick_connect(ip, port)
        time.sleep(delay)

    elapsed = time.time() - start
    print(f"\n✅ Done. {len(ports)} ports probed in {elapsed:.2f}s.")
    print("   Check your sniffer terminal for a 🚨 [SCAN ALERT] line.")


def run_syn_flood_simulation(ip, port=80, count=30, delay=0.05):
    """
    Hit the SAME port repeatedly and fast — this is meant to
    trigger the SYN_FLOOD_THRESHOLD (currently 20 SYNs / 10s)
    rather than the port-scan detector.
    """

    print(f"🔬 Simulating SYN flood against {ip}:{port}")
    print(f"   Sending {count} rapid connection attempts\n")

    start = time.time()

    for i in range(count):
        quick_connect(ip, port, timeout=0.1)
        time.sleep(delay)

    elapsed = time.time() - start
    print(f"\n✅ Done. {count} attempts sent in {elapsed:.2f}s.")
    print("   Check your sniffer terminal for a 🚨 [DOS ALERT] line.")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 trigger_test.py <ip> [num_ports]        (port scan test)")
        print("  python3 trigger_test.py <ip> --flood [count]    (SYN flood test)")
        print("\nExamples:")
        print("  python3 trigger_test.py 127.0.0.1 10")
        print("  python3 trigger_test.py 127.0.0.1 --flood 30")
        sys.exit(1)

    ip = sys.argv[1]

    if "--flood" in sys.argv:
        idx = sys.argv.index("--flood")
        count = int(sys.argv[idx + 1]) if len(sys.argv) > idx + 1 else 30
        run_syn_flood_simulation(ip, count=count)
    else:
        num_ports = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        run_port_scan_simulation(ip, num_ports=num_ports)


if __name__ == "__main__":
    main()
