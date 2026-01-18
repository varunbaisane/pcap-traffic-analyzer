from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap

packets = []

for port in range(20, 50):
    packets.append(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(dport=port))

for _ in range(60):
    packets.append(IP(src="192.168.1.30", dst="8.8.8.8")/UDP()/DNS(qd=DNSQR(qname="example.com")))

for _ in range(120):
    packets.append(IP(src="192.168.1.40", dst="192.168.1.1")/ICMP())

wrpcap("sample.pcap", packets)
print("[+] Sample PCAP generated")
