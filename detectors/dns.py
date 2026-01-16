from collections import defaultdict

def detect_dns_anomaly(packets, threshold=50):
    dns_count = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer("DNS") and pkt.haslayer("IP"):
            src = pkt["IP"].src
            dns_count[src] += 1

    alerts = []
    for src, count in dns_count.items():
        if count >= threshold:
            alerts.append({
                "type": "DNS Anomaly Scan",
                "source_ip": src,
                "query_count": count
            })

    return alerts
