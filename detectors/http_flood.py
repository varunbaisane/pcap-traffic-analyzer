from bisect import bisect_right
from collections import defaultdict
from scapy.layers.http import HTTPRequest

MONITORED_PORTS = {80, 8080, 8000}
MONITORED_METHODS = {b"GET", b"POST", b"HEAD", b"PUT", b"DELETE"}


def detect_http_flood(packets, threshold=50, window=30):
    request_times = defaultdict(list)

    for pkt in packets:
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP") and pkt.haslayer(HTTPRequest)):
            continue
        port = pkt["TCP"].dport
        if port not in MONITORED_PORTS:
            continue
        method = pkt[HTTPRequest].Method
        if method not in MONITORED_METHODS:
            continue
        
        key = (pkt["IP"].src, pkt["IP"].dst)
        request_times[key].append(float(pkt.time))

    alerts = []
    for (src, dst), times in request_times.items():
        times.sort()
        peak = _peak_window_count(times, window)
        if peak >= threshold:
            alerts.append({
                "alert_type": "HTTP Flood",
                "source_ip": src,
                "destination_ip": dst,
                "protocol": "TCP",
                "analyzer": "http_flood_detector",
                "metric": {
                    "attempt_count": peak,
                },
            })

    return alerts


def _peak_window_count(timestamps: list, window: float) -> int:
    peak = 0
    for i, t in enumerate(timestamps):
        count = bisect_right(timestamps, t + window) - i
        if count > peak:
            peak = count
    return peak
