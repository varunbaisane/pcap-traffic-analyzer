def print_alert(alert: dict) -> None:
    """
    Print a single alert to stdout in human-readable format.

    Displays core fields, metrics, MITRE ATT&CK mapping, and LLM enrichment
    data when present.

    Args:
        alert: A fully-formed alert dictionary.
    """
    print(f"[ALERT] {alert.get('alert_type')}  ({alert.get('alert_id')})")
    print(f"  Source IP        : {alert.get('source_ip')}")
    print(f"  Destination IP   : {alert.get('destination_ip')}")
    print(f"  Protocol         : {alert.get('protocol')}")
    print(f"  Analyzer         : {alert.get('analyzer')}")

    timestamp = alert.get("timestamp", {})
    utc_raw = timestamp.get("utc", "")
    local_raw = timestamp.get("local", "")
    utc_display = utc_raw.replace("T", " ").split("+")[0] if utc_raw else "N/A"
    local_display = local_raw.replace("T", " ").split("+")[0] if local_raw else "N/A"
    local_offset = ""
    if local_raw and "+" in local_raw:
        local_offset = "+" + local_raw.split("+")[-1]
    print(f"  Timestamp (UTC)  : {utc_display} UTC")
    print(f"  Timestamp (Local): {local_display} {timestamp.get('timezone', '')}")

    metric = alert.get("metric", {})
    if metric:
        print("  Metrics:")
        for key, value in metric.items():
            pretty_key = key.replace("_", " ").title()
            print(f"    - {pretty_key}: {value}")

    mitre = alert.get("mitre_attack")
    if mitre:
        print("  MITRE ATT&CK:")
        print(f"    - Tactic        : {mitre.get('tactic')}")
        print(
            f"    - Technique     : {mitre.get('technique_id')} "
            f"({mitre.get('technique_name')})"
        )

    llm = alert.get("llm_enrichment")
    if llm:
        status = llm.get("status")
        if status == "failed":
            print(f"  LLM Enrichment   : [FAILED] {llm.get('error', 'Unknown error')}")
        else:
            print("  LLM Enrichment:")
            print(f"    Summary         : {llm.get('summary', 'N/A')}")
            print(f"    Security Context: {llm.get('security_context', 'N/A')}")
            steps = llm.get("investigation_steps", [])
            if steps:
                print("    Investigation Steps:")
                for i, step in enumerate(steps, start=1):
                    print(f"      {i}. {step}")
            print(f"    Model           : {llm.get('analysis_model', 'N/A')}")
            print(f"    Analysed At     : {llm.get('analysis_timestamp', 'N/A')}")

    print("-" * 60)


def print_alerts(alerts: list[dict]) -> None:
    """
    Print all alerts to stdout.

    Args:
        alerts: A list of alert dictionaries to display.
    """
    if not alerts:
        print("[+] No suspicious activity detected.")
        return

    print(f"\n[+] {len(alerts)} alert(s) detected:\n")
    for alert in alerts:
        print_alert(alert)

