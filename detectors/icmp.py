from collections import defaultdict

def detect_icmp_abuse(packets, threshold=100):
    icmp_data = defaultdict(lambda: {
        "packet_count": 0,
        "destination_ip": None
    })

    for pkt in packets:
        if pkt.haslayer("ICMP") and pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst

            icmp_data[src]["packet_count"] += 1
            icmp_data[src]["destination_ip"] = dst

    alerts = []
    for src, data in icmp_data.items():
        if data["packet_count"] >= threshold:
            alerts.append({
                "alert_type": "ICMP Flood",
                "source_ip": src,
                "destination_ip": data["destination_ip"],
                "protocol": "ICMP",
                "analyzer": "icmp_detector",
                "metric": {
                    "icmp_packet_count": data["packet_count"],
                    "packet_count": data["packet_count"]
                }
            })

    return alerts
