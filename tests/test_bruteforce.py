"""Brute force detector validation against the synthetic PCAP dataset."""

import pathlib
import pytest

from utils.pcap_loader import load_pcap
from detectors.bruteforce import detect_brute_force
from utils.mitre_mapping import enrich_with_mitre

SAMPLES = pathlib.Path(__file__).parent.parent / "samples"


def _require(filename: str) -> pathlib.Path:
    path = SAMPLES / filename
    if not path.exists():
        pytest.skip(f"{filename} not found — run: python samples/generate_samples.py")
    return path


def packets(filename: str):
    return load_pcap(str(_require(filename)))


class TestBruteForce:
    def test_threshold_triggers_alert(self):
        alerts = detect_brute_force(packets("bruteforce_threshold.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "Brute Force Attempt"

    def test_threshold_metric_values(self):
        alerts = detect_brute_force(packets("bruteforce_threshold.pcap"))
        assert alerts[0]["metric"]["attempt_count"] == 10
        assert alerts[0]["metric"]["service_port"] == 22

    def test_high_volume_triggers_alert(self):
        alerts = detect_brute_force(packets("bruteforce_high_volume.pcap"))
        assert len(alerts) == 1
        assert alerts[0]["metric"]["attempt_count"] == 25

    def test_below_threshold_no_alert(self):
        alerts = detect_brute_force(packets("bruteforce_below_threshold.pcap"))
        assert len(alerts) == 0

    def test_outside_window_no_alert(self):
        alerts = detect_brute_force(packets("bruteforce_outside_window.pcap"))
        assert len(alerts) == 0

    def test_cross_service_no_alert(self):
        alerts = detect_brute_force(packets("bruteforce_cross_service.pcap"))
        assert len(alerts) == 0

    def test_alert_fields_present(self):
        alerts = detect_brute_force(packets("bruteforce_threshold.pcap"))
        alert = alerts[0]
        for field in ("alert_type", "source_ip", "destination_ip", "protocol", "metric"):
            assert field in alert

    def test_protocol_is_tcp(self):
        alerts = detect_brute_force(packets("bruteforce_threshold.pcap"))
        assert alerts[0]["protocol"] == "TCP"

    def test_non_monitored_ports_ignored(self):
        alerts = detect_brute_force(packets("port_scan_high_volume.pcap"))
        assert len(alerts) == 0


class TestBruteForceMitre:
    def test_mitre_mapping_present(self):
        alert = enrich_with_mitre({"alert_type": "Brute Force Attempt"})
        assert "mitre_attack" in alert

    def test_mitre_tactic(self):
        alert = enrich_with_mitre({"alert_type": "Brute Force Attempt"})
        assert alert["mitre_attack"]["tactic"] == "Credential Access"

    def test_mitre_technique_id(self):
        alert = enrich_with_mitre({"alert_type": "Brute Force Attempt"})
        assert alert["mitre_attack"]["technique_id"] == "T1110"

    def test_mitre_technique_name(self):
        alert = enrich_with_mitre({"alert_type": "Brute Force Attempt"})
        assert alert["mitre_attack"]["technique_name"] == "Brute Force"
