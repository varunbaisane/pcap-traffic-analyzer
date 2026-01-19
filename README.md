# PCAP Traffic Analyzer

A Python-based network forensics tool that analyzes PCAP files to detect suspicious network behavior such as port scanning, DNS anomalies, and ICMP flooding.

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

## How to Run

```bash
pip install -r requirements.txt
#Save your pcap file as samples/sample.pcap
python analyzer.py
```

## Demo

Generate a test PCAP:

```bash
pip install -r requirements.txt
python samples/generate_pcap.py
# Then run the analyzer
python analyzer.py
```

## Output

Alerts are generated in JSON format at `output/alerts.json`.

Example Output:

```json
[
  {
    "type": "Port Scanning",
    "source_ip": "192.168.1.10",
    "ports_scanned": 30,
    "timestamp": "2026-01-19T18:05:52.377166Z"
  },
  {
    "type": "DNS Anomaly Scan",
    "source_ip": "192.168.1.30",
    "query_count": 60,
    "timestamp": "2026-01-19T18:05:52.377179Z"
  },
  {
    "type": "ICMP Flood",
    "source_ip": "192.168.1.40",
    "packet_count": 120,
    "timestamp": "2026-01-19T18:05:52.377182Z"
  }
]
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
