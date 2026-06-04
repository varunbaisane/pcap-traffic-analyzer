"""Generate synthetic PCAP samples for detector validation."""

import pathlib
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap

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

PORT_SCAN_THRESHOLD = 20
DNS_THRESHOLD       = 50
ICMP_THRESHOLD      = 100


def syn_packets(src, dst, port_count, port_start=1024):
    return [
        IP(src=src, dst=dst) / TCP(dport=port_start + i, flags="S")
        for i in range(port_count)
    ]


def dns_packets(src, dst, count):
    return [
        IP(src=src, dst=dst) / UDP(dport=53) / DNS(qd=DNSQR(qname="example.com"))
        for _ in range(count)
    ]


def icmp_packets(src, dst, count):
    return [IP(src=src, dst=dst) / ICMP() for _ in range(count)]


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
         dns_packets(DNS_SRC, DNS_DST, 150) +
         icmp_packets(ICMP_SRC, ICMP_DST, 300))

    save("benign_traffic.pcap",
         syn_packets(BENIGN_SRC_A, SCAN_DST, 10) +
         dns_packets(BENIGN_SRC_B, DNS_DST, 20) +
         icmp_packets(BENIGN_SRC_C, ICMP_DST, 30))

    save("below_threshold_mix.pcap",
         syn_packets(BENIGN_SRC_A, SCAN_DST, PORT_SCAN_THRESHOLD - 1) +
         dns_packets(BENIGN_SRC_B, DNS_DST, DNS_THRESHOLD - 1) +
         icmp_packets(BENIGN_SRC_C, ICMP_DST, ICMP_THRESHOLD - 1))


if __name__ == "__main__":
    main()
