# PyShield Sniffer

A lightweight Python-based network intrusion detector that watches live TCP traffic and flags two common attack patterns in real time:

- **Port scan / reconnaissance** — one source IP touching too many distinct ports in a short window
- **SYN flood (DoS)** — one source IP sending an abnormal rate of SYN packets in a short window

Detections are printed to the console and logged to a JSON report file, structured so they can be fed into a downstream SIEM or dashboard.

## Why this exists

Most simple "detect a port scan" scripts just count packets. PyShield instead uses a **sliding time window** per source IP, so a burst of unrelated traffic doesn't fire a false alarm and an attacker can't evade detection just by slowing down slightly. The two detectors (scan vs. flood) are independent and tuned for different signal types — distinct ports vs. raw packet rate.

## How it works

```
Live TCP traffic
      │
      ▼
packet_callback()  ──filters for pure SYN packets (flags == 0x02)
      │
      ├──> check_smart_port_scan()   tracks unique ports per source IP
      │        over a 10s sliding window → fires if > 3 distinct ports
      │
      └──> check_syn_flood_dos()     tracks SYN rate per source IP
               over a 10s sliding window → fires if > 40 SYNs
      │
      ▼
save_alert_to_json()  ──appends to port_scan_report.json (ring buffer, max 500 entries)
```

## Requirements

- Python 3.9+
- [Npcap](https://npcap.com/) (Windows) or `libpcap` (Linux/Mac)
- `scapy`

```bash
pip install scapy --break-system-packages
```

> **Windows note:** the sniffer requires raw packet capture access, so it must be run from an **Administrator** terminal. Npcap must be installed first.

## Usage

Run the sniffer (Administrator/root required):

```bash
python pyshield_sniffer.py
```

It will sit and listen on your default network interface. Detected events print immediately and are written to `port_scan_report.json` in the working directory.

### Example alert output

```
🚨 [SCAN ALERT] Reconnaissance threat from 192.168.1.50. Targeted > 3 distinct ports within 10s.
🚨 [DOS ALERT] SYN Flood DoS attack from 192.168.1.50 (> 40 SYNs within 10s)
```

### Example JSON output

```json
[
    {
        "source": "packet_sniffer",
        "timestamp": "2026-06-21 14:02:31",
        "alert_type": "PORT_SCAN",
        "attacker_ip": "192.168.1.50",
        "message": "Reconnaissance threat from 192.168.1.50. Targeted > 3 distinct ports within 10s.",
        "status": "ALERT"
    }
]
```

## Testing

Two ways to verify detection actually works, depending on what you want to prove.

### 1. Unit-level test (no network required)

`test_detection_logic.py` feeds synthetic, in-memory packets directly into `packet_callback()`, bypassing the network stack entirely. This proves the detection algorithms themselves are correct, independent of OS/driver/firewall quirks.

```bash
python test_detection_logic.py
```

Expected: both a `🚨 [SCAN ALERT]` and a `🚨 [DOS ALERT]` line, plus a generated `port_scan_report.json` with two entries.

### 2. Live network test (end-to-end)

`trigger_test.py` generates real TCP SYN packets at a target IP, which the sniffer captures off the wire — this proves the whole pipeline works, not just the detection math.

**Terminal 1** (Administrator) — start the sniffer:
```bash
python pyshield_sniffer.py
```

**Terminal 2** — run the trigger script against a **different device on your LAN** (see note below):
```bash
python trigger_test.py <target_ip> 10          # port-scan simulation
python trigger_test.py <target_ip> --flood 50  # SYN-flood simulation
```

> **Important:** target a *different* device on your network (e.g. your phone or another PC's IP), not the machine running the sniffer itself. On Windows, self-to-self traffic is often routed internally by the OS and never actually reaches the network adapter Npcap is capturing on — so testing against `127.0.0.1` or your own LAN IP from the same machine will appear to silently fail even though the sniffer works correctly. This was confirmed during development: identical traffic to a second LAN device was captured immediately, while self-targeted traffic was not.

## Configuration

All detection thresholds are constants at the top of `pyshield_sniffer.py`:

| Constant | Default | Meaning |
|---|---|---|
| `TIME_WINDOW` | `10` (seconds) | Sliding window used by both detectors |
| `UNIQUE_PORTS_THRESHOLD` | `3` | Distinct ports from one IP before a scan alert fires |
| `SYN_FLOOD_THRESHOLD` | `40` | SYN packets from one IP before a flood alert fires |
| `MAX_LOG_RETENTION` | `500` | Max alerts kept in the JSON report (oldest dropped first) |

`UNIQUE_PORTS_THRESHOLD = 3` is tuned to be demonstrably sensitive for testing/demo purposes. On a busy real-world LAN, raising it to 5–8 will reduce false positives from ordinary multi-port traffic (e.g. a browser opening several connections to the same host).

## Known limitations

- Detects only TCP SYN-based scanning/flooding — does not currently inspect UDP, ICMP, or stealth scan types (FIN/NULL/XMAS).
- `save_alert_to_json()` rewrites the entire report file on every alert; fine at this scale, but would need to move to an append-only format (e.g. JSON Lines) for high-throughput production use.
- Single-host detection only — does not currently correlate activity across multiple sniffer instances or hosts.

## License

MIT — see [LICENSE](LICENSE).
