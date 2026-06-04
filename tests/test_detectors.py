"""Automated detector validation against the synthetic PCAP dataset."""

import pathlib
import pytest

from utils.pcap_loader import load_pcap
from detectors.portscan import detect_port_scan
from detectors.dns import detect_dns_anomaly
from detectors.icmp import detect_icmp_abuse
from utils.mitre_mapping import enrich_with_mitre, MITRE_MAPPING
from analyzer import run_detection

SAMPLES = pathlib.Path(__file__).parent.parent / "samples"


def _require(filename: str) -> pathlib.Path:
    path = SAMPLES / filename
    if not path.exists():
        pytest.skip(f"{filename} not found — run: python samples/generate_samples.py")
    return path


def packets(filename: str):
    return load_pcap(str(_require(filename)))


# Port scan detection

class TestPortScan:
    def test_boundary_triggers_alert(self):
        alerts = detect_port_scan(packets("port_scan_boundary.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "Port Scan"

    def test_boundary_metric_at_threshold(self):
        alerts = detect_port_scan(packets("port_scan_boundary.pcap"))
        assert alerts[0]["metric"]["ports_scanned"] == 20

    def test_high_volume_triggers_alert(self):
        alerts = detect_port_scan(packets("port_scan_high_volume.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["metric"]["ports_scanned"] == 50

    def test_below_threshold_no_alert(self):
        alerts = detect_port_scan(packets("below_threshold_mix.pcap"))
        assert len(alerts) == 0

    def test_alert_fields_present(self):
        alerts = detect_port_scan(packets("port_scan_boundary.pcap"))
        alert = alerts[0]
        for field in ("alert_type", "source_ip", "destination_ip", "protocol", "metric"):
            assert field in alert

    def test_protocol_is_tcp(self):
        alerts = detect_port_scan(packets("port_scan_boundary.pcap"))
        assert alerts[0]["protocol"] == "TCP"


# DNS anomaly detection

class TestDnsAnomaly:
    def test_boundary_triggers_alert(self):
        alerts = detect_dns_anomaly(packets("dns_anomaly_boundary.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "DNS Anomaly"

    def test_boundary_metric_at_threshold(self):
        alerts = detect_dns_anomaly(packets("dns_anomaly_boundary.pcap"))
        assert alerts[0]["metric"]["dns_query_count"] == 50

    def test_high_volume_triggers_alert(self):
        alerts = detect_dns_anomaly(packets("dns_anomaly_high_volume.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["metric"]["dns_query_count"] == 150

    def test_below_threshold_no_alert(self):
        alerts = detect_dns_anomaly(packets("below_threshold_mix.pcap"))
        assert len(alerts) == 0

    def test_protocol_is_udp(self):
        alerts = detect_dns_anomaly(packets("dns_anomaly_boundary.pcap"))
        assert alerts[0]["protocol"] == "UDP"


# ICMP flood detection

class TestIcmpFlood:
    def test_boundary_triggers_alert(self):
        alerts = detect_icmp_abuse(packets("icmp_flood_boundary.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "ICMP Flood"

    def test_boundary_metric_at_threshold(self):
        alerts = detect_icmp_abuse(packets("icmp_flood_boundary.pcap"))
        assert alerts[0]["metric"]["icmp_packet_count"] == 100

    def test_high_volume_triggers_alert(self):
        alerts = detect_icmp_abuse(packets("icmp_flood_high_volume.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["metric"]["icmp_packet_count"] == 300

    def test_below_threshold_no_alert(self):
        alerts = detect_icmp_abuse(packets("below_threshold_mix.pcap"))
        assert len(alerts) == 0

    def test_protocol_is_icmp(self):
        alerts = detect_icmp_abuse(packets("icmp_flood_boundary.pcap"))
        assert alerts[0]["protocol"] == "ICMP"


# Mixed attack — all three detectors on a single PCAP

class TestMixedAttack:
    def test_all_three_alert_types_detected(self):
        pkts = packets("mixed_attack.pcap")
        ps  = detect_port_scan(pkts)
        dns = detect_dns_anomaly(pkts)
        icmp = detect_icmp_abuse(pkts)
        assert len(ps)   == 1
        assert len(dns)  == 1
        assert len(icmp) == 1

    def test_alert_types_are_correct(self):
        pkts = packets("mixed_attack.pcap")
        assert detect_port_scan(pkts)[0]["alert_type"]  == "Port Scan"
        assert detect_dns_anomaly(pkts)[0]["alert_type"] == "DNS Anomaly"
        assert detect_icmp_abuse(pkts)[0]["alert_type"]  == "ICMP Flood"

    def test_run_detection_returns_three_alerts(self):
        alerts = run_detection(packets("mixed_attack.pcap"))
        assert len(alerts) == 3

    def test_run_detection_attaches_mitre_to_every_alert(self):
        alerts = run_detection(packets("mixed_attack.pcap"))
        for alert in alerts:
            assert "mitre_attack" in alert

    def test_run_detection_alert_ids_prefixed_correctly(self):
        alerts = run_detection(packets("mixed_attack.pcap"))
        ids = [a["alert_id"] for a in alerts]
        assert any(i.startswith("PS-")   for i in ids)
        assert any(i.startswith("DNS-")  for i in ids)
        assert any(i.startswith("ICMP-") for i in ids)



# Benign traffic — zero alerts expected

class TestBenignTraffic:
    def test_no_port_scan_alert(self):
        assert detect_port_scan(packets("benign_traffic.pcap")) == []

    def test_no_dns_alert(self):
        assert detect_dns_anomaly(packets("benign_traffic.pcap")) == []

    def test_no_icmp_alert(self):
        assert detect_icmp_abuse(packets("benign_traffic.pcap")) == []

    def test_run_detection_returns_zero_alerts(self):
        assert run_detection(packets("benign_traffic.pcap")) == []


# Boundary negative — one step below every threshold

class TestBelowThresholdMix:
    def test_no_alerts_from_any_detector(self):
        pkts = packets("below_threshold_mix.pcap")
        assert detect_port_scan(pkts)  == []
        assert detect_dns_anomaly(pkts) == []
        assert detect_icmp_abuse(pkts)  == []

    def test_run_detection_returns_zero_alerts(self):
        assert run_detection(packets("below_threshold_mix.pcap")) == []


# MITRE mapping correctness

class TestMitreMapping:
    def test_port_scan_mitre(self):
        alert = enrich_with_mitre({"alert_type": "Port Scan"})
        mitre = alert["mitre_attack"]
        assert mitre["tactic"]         == "Discovery"
        assert mitre["technique_id"]   == "T1046"
        assert mitre["technique_name"] == "Network Service Scanning"

    def test_dns_anomaly_mitre(self):
        alert = enrich_with_mitre({"alert_type": "DNS Anomaly"})
        mitre = alert["mitre_attack"]
        assert mitre["tactic"]         == "Command and Control"
        assert mitre["technique_id"]   == "T1071.004"
        assert mitre["technique_name"] == "DNS"

    def test_icmp_flood_mitre(self):
        alert = enrich_with_mitre({"alert_type": "ICMP Flood"})
        mitre = alert["mitre_attack"]
        assert mitre["tactic"]         == "Discovery"
        assert mitre["technique_id"]   == "T1046"
        assert mitre["technique_name"] == "Network Service Scanning"

    def test_unknown_alert_type_no_mitre_key(self):
        alert = enrich_with_mitre({"alert_type": "Unknown"})
        assert "mitre_attack" not in alert

    def test_all_known_types_have_mapping(self):
        for alert_type in ("Port Scan", "DNS Anomaly", "ICMP Flood"):
            assert alert_type in MITRE_MAPPING
