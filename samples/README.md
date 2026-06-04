# Sample PCAPs

Synthetic PCAP files for validating detection logic, boundary conditions, and false-positive behaviour.

All files are generated using Scapy. No real network traffic is included.

---

## Detection Thresholds (reference)

| Detector | Field | Threshold |
|---|---|---|
| Port Scan | Unique destination ports per source IP | ≥ 20 |
| DNS Anomaly | DNS packets per source IP | ≥ 50 |
| ICMP Flood | ICMP packets per source IP | ≥ 100 |

---

## Sample Inventory

| File | Scenario | Expected Alerts | Validation Purpose |
|---|---|---|---|
| `port_scan_boundary.pcap` | 1 source → exactly 20 unique TCP ports | 1 × Port Scan | Boundary — confirms `>=` threshold is inclusive |
| `port_scan_high_volume.pcap` | 1 source → 50 unique TCP ports | 1 × Port Scan | Detection validation — clearly above threshold |
| `dns_anomaly_boundary.pcap` | 1 source → exactly 50 DNS queries | 1 × DNS Anomaly | Boundary — confirms `>=` threshold is inclusive |
| `dns_anomaly_high_volume.pcap` | 1 source → 150 DNS queries | 1 × DNS Anomaly | Detection validation — clearly above threshold |
| `icmp_flood_boundary.pcap` | 1 source → exactly 100 ICMP packets | 1 × ICMP Flood | Boundary — confirms `>=` threshold is inclusive |
| `icmp_flood_high_volume.pcap` | 1 source → 300 ICMP packets | 1 × ICMP Flood | Detection validation — clearly above threshold |
| `mixed_attack.pcap` | 3 sources, each triggering a different detector | 3 alerts (one per type) | Mixed attack — validates independent per-detector operation |
| `benign_traffic.pcap` | 3 sources, all below every threshold | 0 alerts | Benign validation — confirms no false positives at sub-threshold volumes |
| `below_threshold_mix.pcap` | Port Scan: 19 ports · DNS: 49 queries · ICMP: 99 packets | 0 alerts | Boundary negative — one step below every threshold simultaneously |

---

## Sample Descriptions

### `port_scan_boundary.pcap`
One source IP sends SYN packets to exactly 20 unique destination ports on a single target.
Validates that the port scan detector fires at the minimum qualifying count.

### `port_scan_high_volume.pcap`
One source IP sends SYN packets to 50 unique destination ports.
Confirms reliable detection well above the threshold.

### `dns_anomaly_boundary.pcap`
One source IP sends exactly 50 DNS queries to an external resolver.
Validates that the DNS anomaly detector fires at the minimum qualifying count.

### `dns_anomaly_high_volume.pcap`
One source IP sends 150 DNS queries to an external resolver.
Confirms reliable detection well above the threshold.

### `icmp_flood_boundary.pcap`
One source IP sends exactly 100 ICMP echo requests to a single target.
Validates that the ICMP flood detector fires at the minimum qualifying count.

### `icmp_flood_high_volume.pcap`
One source IP sends 300 ICMP echo requests to a single target.
Confirms reliable detection well above the threshold.

### `mixed_attack.pcap`
Three distinct source IPs, each generating a different attack pattern above its respective threshold:
- Source A: port scan (50 ports)
- Source B: DNS anomaly (150 queries)
- Source C: ICMP flood (300 packets)

Validates that all three detectors operate independently on the same PCAP.

### `benign_traffic.pcap`
Three source IPs generating sub-threshold traffic across all three protocols:
- Source A: 10 TCP connections to distinct ports (below port scan threshold)
- Source B: 20 DNS queries (below DNS threshold)
- Source C: 30 ICMP packets (below ICMP threshold)

Expected result: zero alerts. Validates the absence of false positives at normal traffic volumes.

### `below_threshold_mix.pcap`
Three source IPs, each producing traffic exactly one unit below its detector's threshold:
- Source A: 19 unique TCP destination ports (port scan threshold: 20)
- Source B: 49 DNS packets (DNS anomaly threshold: 50)
- Source C: 99 ICMP packets (ICMP flood threshold: 100)

Expected result: zero alerts. Validates that every threshold boundary is exclusive on the lower side,
confirming no off-by-one errors in any detector.


---

## Known Limitations

- The port scan detector is count-based, not time-based. `port_scan_boundary.pcap` and `port_scan_high_volume.pcap` are functionally equivalent in terms of detection; they differ only in metric values reported.
- The DNS detector counts all DNS-layer packets, regardless of query type or domain. `dns_anomaly` samples reflect total packet volume, not unique domains queried.
- The ICMP detector counts all ICMP packets regardless of type (echo, echo reply, unreachable, etc.).
