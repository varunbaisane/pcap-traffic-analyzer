def print_alert(alert):
    print(f"[ALERT] {alert.get('alert_type')}  ({alert.get('alert_id')})")
    print(f"  Source IP        : {alert.get('source_ip')}")
    print(f"  Destination IP   : {alert.get('destination_ip')}")
    print(f"  Protocol         : {alert.get('protocol')}")
    print(f"  Analyzer         : {alert.get('analyzer')}")
    print(f"  Timestamp (UTC)  : {alert.get('timestamp_utc')}")

    metric = alert.get("metric", {})
    if metric:
        print("  Metrics:")
        for key, value in metric.items():
            pretty_key = key.replace("_", " ").title()
            print(f"    - {pretty_key}: {value}")

    print("-" * 60)


def print_alerts(alerts):
    if not alerts:
        print("[+] No suspicious activity detected.")
        return

    print(f"\n[+] {len(alerts)} alert(s) detected:\n")
    for alert in alerts:
        print_alert(alert)
