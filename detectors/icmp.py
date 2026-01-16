from collections import defaultdict

def detect_icmp_abuse(packets, threshold=100):
    icmp_count = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer("ICMP") and pkt.haslayer("IP"):
            src = pkt["IP"].src
            icmp_count[src] += 1

    alerts = []
    for src, count in icmp_count.items():
        if count >= threshold:
            alerts.append({
                "type": "ICMP Flood",
                "source_ip": src,
                "packet_count": count
            })

    return alerts
