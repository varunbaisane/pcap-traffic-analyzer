from collections import defaultdict

def detect_port_scan(packets, threshold=20):
    scan_data = defaultdict(lambda: {
        "ports": set(),
        "packet_count": 0,
        "destination_ip": None
    })

    for pkt in packets:
        if pkt.haslayer("IP") and pkt.haslayer("TCP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst
            dport = pkt["TCP"].dport

            scan_data[src]["ports"].add(dport)
            scan_data[src]["packet_count"] += 1
            scan_data[src]["destination_ip"] = dst

    alerts = []
    for src, data in scan_data.items():
        if len(data["ports"]) >= threshold:
            alerts.append({
                "alert_type": "Port Scan",
                "source_ip": src,
                "destination_ip": data["destination_ip"],
                "protocol": "TCP",
                "analyzer": "portscan_detector",
                "metric": {
                    "ports_scanned": len(data["ports"]),
                    "packet_count": data["packet_count"]
                }
            })

    return alerts
