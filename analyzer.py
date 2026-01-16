import json
from utils.pcap_loader import load_pcap
from detectors.portscan import detect_port_scan
from detectors.dns import detect_dns_anomaly
from detectors.icmp import detect_icmp_abuse

packets = load_pcap("samples/sample.pcap")

alerts = []
alerts.extend(detect_port_scan(packets))
alerts.extend(detect_dns_anomaly(packets))
alerts.extend(detect_icmp_abuse(packets))

with open("output/alerts.json", "w") as f:
    json.dump(alerts, f, indent=4)

print("Analysis completed. \nAlerts saved to output/alerts.json")
