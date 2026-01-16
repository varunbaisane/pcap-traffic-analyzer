from collections import defaultdict

def detect_port_scan(packets, threshold=20):
    scans = defaultdict(set)

    for pkt in packets:
        if pkt.haslayer("IP") and pkt.haslayer("TCP"):
            src = pkt["IP"].src
            dport = pkt["TCP"].dport
            scans[src].add(dport)

    alerts = []
    for src, ports in scans.items():
        if len(ports) >= threshold:
            alerts.append({
                "type": "Port Scanning",
                "source_ip": src,
                "ports_scanned": len(ports)
            })

    return alerts
