"""
test_detection_logic.py
------------------------
Tests your sniffer's detection logic WITHOUT needing real network
sniffing, Npcap, admin rights, or firewall cooperation.

How it works:
  Instead of capturing real packets off the wire, we build fake
  Scapy packet objects in memory (IP/TCP layers with a SYN flag)
  and feed them directly into your packet_callback() function —
  exactly the same function your real sniffer calls for every
  packet it captures.

  If your detection logic (check_smart_port_scan / check_syn_flood_dos)
  is correct, this WILL print the same 🚨 alerts and write the same
  JSON file as a real attack would — because it's running the exact
  same code path, just skipping the "capture packets from the wire"
  step.

Before running:
  1. Save your sniffer file as `pyshield_sniffer.py` in the same folder
  3. pip install scapy --break-system-packages

Run:
  python3 test_detection_logic.py
"""

import time
from scapy.layers.inet import IP, TCP

# ---------------------------------------------------------------
# Import your sniffer module.
# Change "sniffer" to whatever you named your file (without .py)
# ---------------------------------------------------------------
import pyshield_sniffer  # <-- rename this to match your actual filename


def make_fake_syn_packet(src_ip, dst_port, dst_ip="10.0.0.99"):
    """
    Build a fake SYN packet entirely in memory — no network
    involved at all. This is what scapy would hand to
    packet_callback() if it had really captured this packet.
    """
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, flags="S")
    return pkt


def test_port_scan_detection():
    print("\n" + "=" * 60)
    print("TEST 1: Port Scan Detection")
    print("=" * 60)
    print(f"Threshold in your code: "
          f"> {pyshield_sniffer.UNIQUE_PORTS_THRESHOLD} unique ports "
          f"within {pyshield_sniffer.TIME_WINDOW}s")

    attacker_ip = "203.0.113.50"  # fake "attacker" IP, doesn't need to be real
    ports_to_hit = [21, 22, 23, 80, 443, 8080]  # 6 ports > threshold of 3

    print(f"\nFeeding {len(ports_to_hit)} fake SYN packets "
          f"from {attacker_ip} to packet_callback()...\n")

    for port in ports_to_hit:
        pkt = make_fake_syn_packet(attacker_ip, port)
        print(f"  → feeding fake SYN: {attacker_ip} -> port {port}")
        pyshield_sniffer.packet_callback(pkt)
        time.sleep(0.1)  # tiny delay, stays well inside the 10s window

    print("\nIf you saw a 🚨 [SCAN ALERT] line above, detection WORKS.")


def test_syn_flood_detection():
    print("\n" + "=" * 60)
    print("TEST 2: SYN Flood Detection")
    print("=" * 60)
    print(f"Threshold in your code: "
          f"> {pyshield_sniffer.SYN_FLOOD_THRESHOLD} SYNs "
          f"within {pyshield_sniffer.TIME_WINDOW}s")

    attacker_ip = "203.0.113.99"
    target_port = 80
    num_packets = pyshield_sniffer.SYN_FLOOD_THRESHOLD + 5  # comfortably over threshold

    print(f"\nFeeding {num_packets} fake SYN packets "
          f"from {attacker_ip} to port {target_port}...\n")

    for i in range(num_packets):
        pkt = make_fake_syn_packet(attacker_ip, target_port)
        pyshield_sniffer.packet_callback(pkt)
        if (i + 1) % 5 == 0:
            print(f"  → sent {i + 1}/{num_packets}")

    print("\nIf you saw a 🚨 [DOS ALERT] line above, detection WORKS.")


def show_resulting_report():
    import json
    import os

    print("\n" + "=" * 60)
    print("Resulting JSON report")
    print("=" * 60)

    if not os.path.exists(pyshield_sniffer.OUTPUT_FILE):
        print(f"❌ {pyshield_sniffer.OUTPUT_FILE} was not created — "
              f"something is wrong with save_alert_to_json().")
        return

    with open(pyshield_sniffer.OUTPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"✅ {pyshield_sniffer.OUTPUT_FILE} contains {len(data)} alert(s):\n")
    for alert in data:
        print(f"  [{alert['alert_type']}] {alert['attacker_ip']} — "
              f"{alert['message']}")


if __name__ == "__main__":
    test_port_scan_detection()
    test_syn_flood_detection()
    show_resulting_report()
