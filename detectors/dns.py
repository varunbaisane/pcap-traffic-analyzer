from collections import defaultdict

def detect_dns_anomaly(packets, threshold=50):
    dns_data = defaultdict(lambda: {
        "packet_count": 0,
        "destination_ip": None
    })

    for pkt in packets:
        if pkt.haslayer("DNS") and pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst

            dns_data[src]["packet_count"] += 1
            dns_data[src]["destination_ip"] = dst

    alerts = []
    for src, data in dns_data.items():
        if data["packet_count"] >= threshold:
            alerts.append({
                "alert_type": "DNS Anomaly",
                "source_ip": src,
                "destination_ip": data["destination_ip"],
                "protocol": "UDP",
                "analyzer": "dns_anomaly_detector",
                "metric": {
                    "dns_query_count": data["packet_count"],
                    "packet_count": data["packet_count"]
                }
            })

    return alerts
