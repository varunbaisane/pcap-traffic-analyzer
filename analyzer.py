import json
import argparse
from datetime import datetime, timezone

from utils.pcap_loader import load_pcap
from detectors.portscan import detect_port_scan
from detectors.dns import detect_dns_anomaly
from detectors.icmp import detect_icmp_abuse
from utils.console_output import print_alerts
from utils.mitre_mapping import enrich_with_mitre

def enrich_alerts(alerts, prefix):
    enriched = []
    for index, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"{prefix}-{index:03d}"
        alert["timestamp"] = {
            "utc": datetime.now(timezone.utc).isoformat(),
            "date": datetime.now(timezone.utc).date().isoformat(),
            "time": datetime.now(timezone.utc).time().replace(microsecond=0).isoformat()
        }
        alert = enrich_with_mitre(alert)
        enriched.append(alert)
    return enriched


def main():
    parser = argparse.ArgumentParser(
        description="PCAP Traffic Analyzer – Core Detection Engine"
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to the PCAP file to analyze"
    )

    args = parser.parse_args()
    packets = load_pcap(args.pcap)

    alerts = []
    alerts.extend(enrich_alerts(detect_port_scan(packets), "PS"))
    alerts.extend(enrich_alerts(detect_dns_anomaly(packets), "DNS"))
    alerts.extend(enrich_alerts(detect_icmp_abuse(packets), "ICMP"))

    with open("output/alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"[+] Analysis complete. {len(alerts)} alerts generated.")
    print("[+] Results saved to output/alerts.json")

    print_alerts(alerts)

if __name__ == "__main__":
    main()
