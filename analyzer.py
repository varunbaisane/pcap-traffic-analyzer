import json
import logging
import argparse
import os
import pathlib
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

from utils.pcap_loader import load_pcap
from detectors.portscan import detect_port_scan
from detectors.dns import detect_dns_anomaly
from detectors.icmp import detect_icmp_abuse
from utils.console_output import print_alerts
from utils.mitre_mapping import enrich_with_mitre

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


def _get_local_timezone_name() -> str:
    """
    Detect the IANA timezone name of the host system.

    Uses a cascade of OS-level strategies to maximise portability:
    1. /etc/localtime symlink target (Linux/macOS)
    2. /etc/timezone file contents (Debian/Ubuntu)
    3. TZ environment variable
    4. Falls back to the abbreviation from the OS (e.g. "IST", "EST")

    Returns:
        A timezone identifier such as "Asia/Kolkata" or "EST".
    """
    localtime = pathlib.Path("/etc/localtime")
    if localtime.is_symlink():
        target = str(localtime.resolve())
        if "zoneinfo/" in target:
            return target.split("zoneinfo/")[-1]

    tz_file = pathlib.Path("/etc/timezone")
    if tz_file.exists():
        name = tz_file.read_text().strip()
        if name:
            return name

    tz_env = os.environ.get("TZ")
    if tz_env:
        return tz_env

    return datetime.now().astimezone().tzname() or "UTC"


def _enrich_with_metadata(alerts: list[dict], prefix: str) -> list[dict]:
    """
    Attach alert IDs, timestamps, and MITRE mappings to a list of alerts.

    Timestamps include both UTC and local representations with the host
    system's IANA timezone identifier for unambiguous interpretation.

    Args:
        alerts: Raw alert dicts as produced by a detector.
        prefix: Short prefix string for the alert ID (e.g. "PS", "DNS").

    Returns:
        The same list with `alert_id`, `timestamp`, and `mitre_attack` added
        to each entry.
    """
    tz_name = _get_local_timezone_name()
    enriched: list[dict] = []
    for index, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"{prefix}-{index:03d}"
        now_utc = datetime.now(timezone.utc).replace(microsecond=0)
        now_local = now_utc.astimezone()
        alert["timestamp"] = {
            "utc": now_utc.isoformat(),
            "local": now_local.isoformat(),
            "timezone": tz_name,
        }
        alert = enrich_with_mitre(alert)
        enriched.append(alert)
    return enriched


def _build_argument_parser() -> argparse.ArgumentParser:
    """
    Construct and return the CLI argument parser.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="PCAP Traffic Analyzer – Core Detection Engine"
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to the PCAP file to analyse",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        default=False,
        help=(
            "Enrich alerts with LLM-generated security context. "
            "Requires GEMINI_API_KEY to be set."
        ),
    )
    return parser


def main() -> None:
    """
    Entry point for the PCAP Traffic Analyzer.

    Parses CLI arguments, loads the PCAP file, runs all detectors,
    optionally performs LLM enrichment, and writes results to disk.
    """
    parser = _build_argument_parser()
    args = parser.parse_args()

    packets = load_pcap(args.pcap)

    alerts: list[dict] = []
    alerts.extend(_enrich_with_metadata(detect_port_scan(packets), "PS"))
    alerts.extend(_enrich_with_metadata(detect_dns_anomaly(packets), "DNS"))
    alerts.extend(_enrich_with_metadata(detect_icmp_abuse(packets), "ICMP"))

    if args.llm:
        from utils.llm.enricher import enrich_alerts as llm_enrich_alerts
        from utils.llm.gemini_backend import GeminiBackend

        try:
            backend = GeminiBackend()
            print(f"[+] LLM enrichment enabled (model: {backend.model_name})")
            alerts = llm_enrich_alerts(alerts, backend)
        except EnvironmentError as exc:
            print(f"[!] LLM enrichment skipped: {exc}")
            logger.warning("LLM backend initialisation failed: %s", exc)

    with open("output/alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)

    print(f"[+] Analysis complete. {len(alerts)} alerts generated.")
    print("[+] Results saved to output/alerts.json")

    print_alerts(alerts)


if __name__ == "__main__":
    main()
