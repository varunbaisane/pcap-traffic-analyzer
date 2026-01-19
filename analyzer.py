import json
import argparse
from datetime import datetime

from utils.pcap_loader import load_pcap
from detectors.portscan import detect_port_scan
from detectors.dns import detect_dns_anomaly
from detectors.icmp import detect_icmp_abuse


def add_timestamp(alert):
    alert["timestamp"] = "UTC: " +datetime.utcnow().isoformat() + "Z"
    return alert


def main():
    parser = argparse.ArgumentParser(
        description="PCAP Traffic Analyzer for detecting suspicious network activity"
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to the PCAP file to analyze"
    )

    args = parser.parse_args()

    packets = load_pcap(args.pcap)

    alerts = []
    alerts.extend(detect_port_scan(packets))
    alerts.extend(detect_dns_anomaly(packets))
    alerts.extend(detect_icmp_abuse(packets))

    # Add timestamp to each alert
    alerts = [add_timestamp(alert) for alert in alerts]

    with open("output/alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"[+] Analysis complete. {len(alerts)} alerts generated.")
    print("[+] Results saved to output/alerts.json")


if __name__ == "__main__":
    main()
