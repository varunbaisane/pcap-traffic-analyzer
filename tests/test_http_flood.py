"""HTTP Flood detector validation against the synthetic PCAP dataset."""

import pathlib
import pytest

from utils.pcap_loader import load_pcap
from detectors.http_flood import detect_http_flood
from utils.mitre_mapping import enrich_with_mitre

SAMPLES = pathlib.Path(__file__).parent.parent / "samples"


def _require(filename: str) -> pathlib.Path:
    path = SAMPLES / filename
    if not path.exists():
        pytest.skip(f"{filename} not found — run: python samples/generate_samples.py")
    return path


def packets(filename: str):
    return load_pcap(str(_require(filename)))


class TestHttpFlood:
    def test_threshold_triggers_alert(self):
        alerts = detect_http_flood(packets("http_flood_threshold.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "HTTP Flood"
        assert alerts[0]["metric"]["attempt_count"] == 50

    def test_high_volume_triggers_alert(self):
        alerts = detect_http_flood(packets("http_flood_high_volume.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["metric"]["attempt_count"] == 100

    def test_below_threshold_no_alert(self):
        alerts = detect_http_flood(packets("http_flood_below_threshold.pcap"))
        assert len(alerts) == 0

    def test_cross_host_isolation_no_alert(self):
        alerts = detect_http_flood(packets("http_flood_cross_host.pcap"))
        assert len(alerts) == 0

    def test_cross_port_aggregation_alert(self):
        alerts = detect_http_flood(packets("http_flood_cross_port.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["metric"]["attempt_count"] == 50

    def test_outside_window_enforcement_no_alert(self):
        alerts = detect_http_flood(packets("http_flood_outside_window.pcap"))
        assert len(alerts) == 0

    def test_alert_fields_present(self):
        alerts = detect_http_flood(packets("http_flood_threshold.pcap"))
        alert = alerts[0]
        for field in ("alert_type", "source_ip", "destination_ip", "protocol", "metric"):
            assert field in alert

    def test_protocol_is_tcp(self):
        alerts = detect_http_flood(packets("http_flood_threshold.pcap"))
        assert alerts[0]["protocol"] == "TCP"

    def test_non_monitored_ports_ignored(self):
        alerts = detect_http_flood(packets("bruteforce_high_volume.pcap"))
        assert len(alerts) == 0

    def test_supported_methods_only(self):
        alerts = detect_http_flood(packets("port_scan_high_volume.pcap"))
        assert len(alerts) == 0


class TestHttpFloodMitre:
    def test_mitre_mapping_present(self):
        alert = enrich_with_mitre({"alert_type": "HTTP Flood"})
        assert "mitre_attack" in alert

    def test_mitre_tactic(self):
        alert = enrich_with_mitre({"alert_type": "HTTP Flood"})
        assert alert["mitre_attack"]["tactic"] == "Impact"

    def test_mitre_technique_id(self):
        alert = enrich_with_mitre({"alert_type": "HTTP Flood"})
        assert alert["mitre_attack"]["technique_id"] == "T1498"

    def test_mitre_technique_name(self):
        alert = enrich_with_mitre({"alert_type": "HTTP Flood"})
        assert alert["mitre_attack"]["technique_name"] == "Network Denial of Service"
