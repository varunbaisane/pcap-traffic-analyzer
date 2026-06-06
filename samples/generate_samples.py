"""Generate synthetic PCAP samples for detector validation."""

import pathlib
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Packet, wrpcap
from scapy.layers.http import HTTPRequest

SAMPLES_DIR = pathlib.Path(__file__).parent

SCAN_SRC     = "10.0.0.10"
SCAN_DST     = "10.0.0.20"
DNS_SRC      = "10.0.0.30"
DNS_DST      = "8.8.8.8"
ICMP_SRC     = "10.0.0.40"
ICMP_DST     = "10.0.0.1"
BENIGN_SRC_A = "10.0.0.50"
BENIGN_SRC_B = "10.0.0.51"
BENIGN_SRC_C = "10.0.0.52"

PORT_SCAN_THRESHOLD  = 20
DNS_THRESHOLD        = 50
ICMP_THRESHOLD       = 100
BRUTE_FORCE_THRESHOLD = 10
HTTP_FLOOD_THRESHOLD = 50

BF_SRC = "10.0.1.10"
BF_DST = "10.0.1.20"

HF_SRC = "10.0.2.10"
HF_DST = "10.0.2.20"
HF_DST_B = "10.0.2.30"

BASE_TIME = 1_700_000_000.0


def timed_packets(packet_factory, count: int, duration: float, base: float = BASE_TIME) -> list[Packet]:

    interval = 0.0 if (count <= 1 or duration == 0) else duration / (count - 1)
    pkts = []
    for i in range(count):
        pkt = packet_factory(i)
        pkt.time = base + i * interval
        pkts.append(pkt)
    return pkts


def syn_packets(src, dst, port_count, duration=10.0, port_start=1024, base=BASE_TIME):
    return timed_packets(
        lambda i: IP(src=src, dst=dst) / TCP(dport=port_start + i, flags="S"),
        port_count, duration, base,
    )


def dns_packets(src, dst, count, duration=60.0, base=BASE_TIME):
    return timed_packets(
        lambda i: IP(src=src, dst=dst) / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com")),
        count, duration, base,
    )


def icmp_packets(src, dst, count, duration=30.0, base=BASE_TIME):
    return timed_packets(
        lambda i: IP(src=src, dst=dst) / ICMP(),
        count, duration, base,
    )


def bf_syn_packets(src, dst, port, count, duration=30.0, base=BASE_TIME):
    return timed_packets(
        lambda i: IP(src=src, dst=dst) / TCP(dport=port, flags="S"),
        count, duration, base,
    )


def http_packets(src, dst, port, method, count, duration=30.0, base=BASE_TIME):
    return timed_packets(
        lambda i: IP(src=src, dst=dst) / TCP(dport=port, flags="PA", sport=10000+i) / HTTPRequest(Method=method, Path=b"/", Http_Version=b"HTTP/1.1", Host=dst.encode()),
        count, duration, base,
    )


def save(filename, packets):
    wrpcap(str(SAMPLES_DIR / filename), packets)
    print(f"[+] {filename} ({len(packets)} packets)")


def main():
    save("port_scan_boundary.pcap",
         syn_packets(SCAN_SRC, SCAN_DST, PORT_SCAN_THRESHOLD))

    save("port_scan_high_volume.pcap",
         syn_packets(SCAN_SRC, SCAN_DST, 50))

    save("dns_anomaly_boundary.pcap",
         dns_packets(DNS_SRC, DNS_DST, DNS_THRESHOLD))

    save("dns_anomaly_high_volume.pcap",
         dns_packets(DNS_SRC, DNS_DST, 150))

    save("icmp_flood_boundary.pcap",
         icmp_packets(ICMP_SRC, ICMP_DST, ICMP_THRESHOLD))

    save("icmp_flood_high_volume.pcap",
         icmp_packets(ICMP_SRC, ICMP_DST, 300))

    save("mixed_attack.pcap",
         syn_packets(SCAN_SRC, SCAN_DST, 50) +
         dns_packets(DNS_SRC, DNS_DST, 150, base=BASE_TIME + 300) +
         icmp_packets(ICMP_SRC, ICMP_DST, 300, base=BASE_TIME + 600))

    save("benign_traffic.pcap",
         syn_packets(BENIGN_SRC_A, SCAN_DST, 10) +
         dns_packets(BENIGN_SRC_B, DNS_DST, 20) +
         icmp_packets(BENIGN_SRC_C, ICMP_DST, 30))

    save("below_threshold_mix.pcap",
         syn_packets(BENIGN_SRC_A, SCAN_DST, PORT_SCAN_THRESHOLD - 1) +
         dns_packets(BENIGN_SRC_B, DNS_DST, DNS_THRESHOLD - 1) +
         icmp_packets(BENIGN_SRC_C, ICMP_DST, ICMP_THRESHOLD - 1))

    save("bruteforce_threshold.pcap",
         bf_syn_packets(BF_SRC, BF_DST, 22, BRUTE_FORCE_THRESHOLD))

    save("bruteforce_high_volume.pcap",
         bf_syn_packets(BF_SRC, BF_DST, 22, 25))

    save("bruteforce_below_threshold.pcap",
         bf_syn_packets(BF_SRC, BF_DST, 22, BRUTE_FORCE_THRESHOLD - 1))

    save("bruteforce_cross_service.pcap",
         bf_syn_packets(BF_SRC, BF_DST, 22, 5) +
         bf_syn_packets(BF_SRC, BF_DST, 21, 5))

    save("bruteforce_outside_window.pcap",
         bf_syn_packets(BF_SRC, BF_DST, 22, BRUTE_FORCE_THRESHOLD, duration=150.0))

    save("http_flood_threshold.pcap",
         http_packets(HF_SRC, HF_DST, 80, b"GET", HTTP_FLOOD_THRESHOLD))

    save("http_flood_high_volume.pcap",
         http_packets(HF_SRC, HF_DST, 80, b"GET", 100, duration=10.0))

    save("http_flood_below_threshold.pcap",
         http_packets(HF_SRC, HF_DST, 80, b"GET", HTTP_FLOOD_THRESHOLD - 1))

    save("http_flood_cross_host.pcap",
         http_packets(HF_SRC, HF_DST, 80, b"GET", 25) +
         http_packets(HF_SRC, HF_DST_B, 80, b"GET", 25))

    save("http_flood_cross_port.pcap",
         http_packets(HF_SRC, HF_DST, 80, b"GET", 25) +
         http_packets(HF_SRC, HF_DST, 8080, b"GET", 25))

    save("http_flood_outside_window.pcap",
         http_packets(HF_SRC, HF_DST, 80, b"GET", HTTP_FLOOD_THRESHOLD, duration=120.0))


if __name__ == "__main__":
    main()
