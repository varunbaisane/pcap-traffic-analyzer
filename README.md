# PCAP Traffic Analyzer

A Python-based network forensics tool that analyzes PCAP files and detects suspicious network activity such as port scanning, DNS anomalies, and ICMP flooding.  
The tool produces **structured SOC-style alerts** in JSON format along with **human-readable console output**.

### Project Objective

This project demonstrates practical network security and detection skills by inspecting packet-level traffic and identifying common attack patterns using rule-based analysis.

### Detection Capabilities

1. **Port Scanning Detection**
   - Identifies hosts scanning multiple ports on a target
2. **DNS Anomaly Detection**
   - Flags excessive DNS queries that may indicate tunneling or malware
3. **ICMP Abuse Detection**
   - Detects abnormal ICMP traffic often associated with reconnaissance or DoS activity

## Tech Stack

- Python
- Scapy
- JSON-based alerting

## Demo

```bash
git clone <your-repo-url>
pip install -r requirements.txt
#To check analyzer with sample pcap file OR save your file as samples/sample.pcap
python samples/generate_pcap.py
python analyzer.py --pcap samples/sample.pcap
```

## Output

### JSON Output:

Alerts are generated in JSON format at `output/alerts.json`.

Example Output:

```json
[
  {
    "alert_type": "Port Scan",
    "source_ip": "192.168.1.10",
    "destination_ip": "192.168.1.20",
    "protocol": "TCP",
    "analyzer": "portscan_detector",
    "metric": {
      "ports_scanned": 30,
      "packet_count": 30
    },
    "alert_id": "PS-001",
    "timestamp_utc": "2026-01-30T19:47:27.090375Z"
  },
  {
    "alert_type": "DNS Anomaly",
    "source_ip": "192.168.1.30",
    "destination_ip": "8.8.8.8",
    "protocol": "UDP",
    "analyzer": "dns_anomaly_detector",
    "metric": {
      "dns_query_count": 60,
      "packet_count": 60
    },
    "alert_id": "DNS-001",
    "timestamp_utc": "2026-01-30T19:47:27.091260Z"
  },
  {
    "alert_type": "ICMP Flood",
    "source_ip": "192.168.1.40",
    "destination_ip": "192.168.1.1",
    "protocol": "ICMP",
    "analyzer": "icmp_detector",
    "metric": {
      "icmp_packet_count": 120,
      "packet_count": 120
    },
    "alert_id": "ICMP-001",
    "timestamp_utc": "2026-01-30T19:47:27.092308Z"
  }
]
```

### Console Output:

Human readable output in the console itself.

```bash
[+] Analysis complete. 3 alerts generated.
[+] Results saved to output/alerts.json

[+] 3 alert(s) detected:

[ALERT] Port Scan  (PS-001)
  Source IP        : 192.168.1.10
  Destination IP   : 192.168.1.20
  Protocol         : TCP
  Analyzer         : portscan_detector
  Timestamp (UTC)  : 2026-01-30T19:47:27.090375Z
  Metrics:
    - Ports Scanned: 30
    - Packet Count: 30
------------------------------------------------------------
[ALERT] DNS Anomaly  (DNS-001)
  Source IP        : 192.168.1.30
  Destination IP   : 8.8.8.8
  Protocol         : UDP
  Analyzer         : dns_anomaly_detector
  Timestamp (UTC)  : 2026-01-30T19:47:27.091260Z
  Metrics:
    - Dns Query Count: 60
    - Packet Count: 60
------------------------------------------------------------
[ALERT] ICMP Flood  (ICMP-001)
  Source IP        : 192.168.1.40
  Destination IP   : 192.168.1.1
  Protocol         : ICMP
  Analyzer         : icmp_detector
  Timestamp (UTC)  : 2026-01-30T19:47:27.092308Z
  Metrics:
    - Icmp Packet Count: 120
    - Packet Count: 120
------------------------------------------------------------
```

## Use Case

- Network forensics
- SOC analyst practice
- Blue team training
- CTF / academic learning

## Future Improvements

- AI-based alert explanation
- Dockerized execution
- Convert into a CLI Tool
- Add MITRE ATT&CK Mapping
