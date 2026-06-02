# PCAP Traffic Analyzer

A Python-based network forensics tool that analyses PCAP files and detects suspicious network activity — including port scanning, DNS anomalies, and ICMP flooding.

The tool produces **structured SOC-style alerts** in JSON format with optional **LLM-powered enrichment** via Google Gemini.

---

## Project Objective

Demonstrates practical network security and detection skills by inspecting packet-level traffic, identifying common attack patterns through rule-based analysis, and enriching alerts with AI-generated investigation context.

---

## Detection Capabilities

| Detector | Description |
|---|---|
| **Port Scan Detection** | Identifies hosts scanning multiple ports on a target |
| **DNS Anomaly Detection** | Flags excessive DNS queries that may indicate tunneling or malware C2 |
| **ICMP Abuse Detection** | Detects abnormal ICMP traffic associated with reconnaissance or DoS |

---

## Tech Stack

- **Python 3.12+**
- **Scapy** — PCAP parsing
- **Google Gemini** (`google-genai`) — optional LLM enrichment
- **python-dotenv** — environment variable management
- **JSON** — structured alert output

---

## Installation

```bash
git clone <your-repo-url>
cd pcap-traffic-analyzer
pip install -r requirements.txt
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

`.env` file:

```
GEMINI_API_KEY=your_google_ai_studio_key_here
GEMINI_MODEL=gemini-2.5-flash   # optional, this is the default
```

Get a free API key at [Google AI Studio](https://aistudio.google.com/app/apikey).

---

## Usage

### Standard Analysis

```bash
python analyzer.py --pcap samples/sample.pcap
```

### With LLM Enrichment

```bash
python analyzer.py --pcap samples/sample.pcap --llm
```

The `--llm` flag is fully optional. Without it, the tool behaves exactly as before — no API calls are made and no API key is required.

### Generate a sample PCAP

```bash
python samples/generate_pcap.py
python analyzer.py --pcap samples/sample.pcap
```

---

## Output

Results are written to `output/alerts.json`.

### JSON Alert Schema (without LLM)

```json
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
  "timestamp": {
    "utc": "2026-03-08T14:12:11+00:00",
    "date": "2026-03-08",
    "time": "14:12:11"
  },
  "mitre_attack": {
    "tactic": "Discovery",
    "technique_id": "T1046",
    "technique_name": "Network Service Scanning"
  }
}
```

### JSON Alert Schema (with `--llm`)

The `llm_enrichment` block is appended to each alert:

```json
{
  "alert_type": "Port Scan",
  "...": "...",
  "llm_enrichment": {
    "summary": "Host 192.168.1.10 scanned 30 ports on 192.168.1.20 via TCP, consistent with automated network service enumeration.",
    "security_context": "Port scanning is commonly performed by attackers during the Discovery phase to identify open services and potential attack vectors.",
    "investigation_steps": [
      "Correlate 192.168.1.10 against known asset inventory to determine if scanning is authorized.",
      "Review firewall and IDS logs for the same source IP around the scan timestamp.",
      "Check whether any scanned ports were subsequently accessed by the same host."
    ],
    "analysis_model": "gemini-2.5-flash",
    "analysis_timestamp": "2026-03-08T14:12:15+00:00"
  }
}
```

### Console Output

```
[+] LLM enrichment enabled (model: gemini-2.5-flash)
[+] Analysis complete. 3 alerts generated.
[+] Results saved to output/alerts.json

[+] 3 alert(s) detected:

[ALERT] Port Scan  (PS-001)
  Source IP        : 192.168.1.10
  Destination IP   : 192.168.1.20
  Protocol         : TCP
  Analyzer         : portscan_detector
  Timestamp (UTC)  : 2026-03-08 14:12:11
  Metrics:
    - Ports Scanned: 30
    - Packet Count: 30
  MITRE ATT&CK:
    - Tactic        : Discovery
    - Technique     : T1046 (Network Service Scanning)
  LLM Enrichment:
    Summary         : Host 192.168.1.10 scanned 30 ports...
    Security Context: Port scanning is commonly performed...
    Investigation Steps:
      1. Correlate 192.168.1.10 against known asset inventory...
      2. Review firewall and IDS logs...
      3. Check whether any scanned ports were subsequently accessed...
    Model           : gemini-2.5-flash
    Analysed At     : 2026-03-08T14:12:15+00:00
------------------------------------------------------------
```

---

## Architecture

```
PCAP
 └─▶ Detection Engine (Scapy)
      └─▶ MITRE ATT&CK Mapping
           └─▶ [Optional] LLM Enrichment (Gemini)
                └─▶ JSON Output + Console Display
```

### LLM Module Structure

```
utils/llm/
├── __init__.py          # Package marker
├── base.py              # Abstract LLMBackend interface
├── prompt_builder.py    # Backend-agnostic prompt construction
├── enricher.py          # Orchestration layer (dependency injection)
└── gemini_backend.py    # Google Gemini implementation
```

The backend is pluggable. Adding a new provider (Ollama, Anthropic, local LLM) requires only a new `*_backend.py` file that subclasses `LLMBackend`.

---

## Use Case

- Network forensics
- SOC analyst practice
- Blue team training
- CTF / academic learning

---

## Future Improvements

- Dockerized execution
- CLI packaging (`pip install pcap-analyzer`)
- Stage 2 / Stage 3 MITRE ATT&CK mapping
- ML-based anomaly scoring layer
- Additional backend support (Ollama, local LLMs)
