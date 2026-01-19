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

