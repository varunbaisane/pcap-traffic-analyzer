from bisect import bisect_right
from collections import defaultdict

MONITORED_PORTS = {21, 22, 23, 3389}


def detect_brute_force(packets, threshold=10, window=60):
    syn_times = defaultdict(list)

    for pkt in packets:
        if not (pkt.haslayer("IP") and pkt.haslayer("TCP")):
            continue
        if int(pkt["TCP"].flags) != 0x02:
            continue
        port = pkt["TCP"].dport
        if port not in MONITORED_PORTS:
            continue
        key = (pkt["IP"].src, pkt["IP"].dst, port)
        syn_times[key].append(float(pkt.time))

    alerts = []
    for (src, dst, port), times in syn_times.items():
        times.sort()
        peak = _peak_window_count(times, window)
        if peak >= threshold:
            alerts.append({
                "alert_type": "Brute Force Attempt",
                "source_ip": src,
                "destination_ip": dst,
                "protocol": "TCP",
                "analyzer": "bruteforce_detector",
                "metric": {
                    "service_port": port,
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
