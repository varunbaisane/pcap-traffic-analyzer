# Sample PCAPs

Synthetic PCAP files for validating detection logic, boundary conditions, and false-positive behaviour.

PCAP files are excluded from version control. Run the generator to recreate the full dataset:

```bash
python samples/generate_samples.py
```

All files are produced deterministically by `generate_samples.py`. Repeated runs produce identical output.

---

## Detection Thresholds (reference)

| Detector | Field | Threshold |
|---|---|---|
| Port Scan | Unique destination ports per source IP | ≥ 20 |
| DNS Anomaly | DNS packets per source IP | ≥ 50 |
| ICMP Flood | ICMP packets per source IP | ≥ 100 |
| Brute Force | TCP SYN packets per (source IP, destination IP, port) in 60s window | ≥ 10 |
| HTTP Flood | HTTP requests per (source IP, destination IP) in 30s window | ≥ 50 |

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
| `bruteforce_threshold.pcap` | 10 SYN to SSH (port 22) over 30s | 1 × Brute Force Attempt | Detection validation — at threshold within window |
| `bruteforce_high_volume.pcap` | 25 SYN to SSH (port 22) over 30s | 1 × Brute Force Attempt | Detection validation — clearly above threshold |
| `bruteforce_below_threshold.pcap` | 9 SYN to SSH (port 22) over 30s | 0 alerts | Boundary negative — one below threshold |
| `bruteforce_cross_service.pcap` | 5 SYN to SSH + 5 SYN to FTP, same src/dst, same time window | 0 alerts | Per-port isolation — counts are not combined across ports |
| `bruteforce_outside_window.pcap` | 10 SYN to SSH over 150s (exceeds 60s window) | 0 alerts | Window negative — max 4 SYN in any 60s window |
| `http_flood_threshold.pcap` | 50 GET requests to port 80 over 30s | 1 × HTTP Flood | Detection validation — at threshold within window |
| `http_flood_high_volume.pcap` | 100 GET requests to port 80 over 10s | 1 × HTTP Flood | Detection validation — clearly above threshold |
| `http_flood_below_threshold.pcap` | 49 GET requests to port 80 over 30s | 0 alerts | Boundary negative — one below threshold |
| `http_flood_cross_host.pcap` | 25 requests to Host A + 25 requests to Host B | 0 alerts | Per-host isolation — counts are not combined across destinations |
| `http_flood_cross_port.pcap` | 25 requests to port 80 + 25 requests to port 8080, same src/dst | 1 × HTTP Flood | Cross-port aggregation — counts are combined across ports to the same host |
| `http_flood_outside_window.pcap` | 50 GET requests to port 80 over 120s (exceeds 30s window) | 0 alerts | Window negative — max requests in any 30s window is below 50 |

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

### `bruteforce_threshold.pcap`
One source IP sends 10 TCP SYN packets to SSH (port 22) on a single target over 30 seconds.
Validates that the brute force detector fires at the minimum qualifying count within the 60-second window.

### `bruteforce_high_volume.pcap`
One source IP sends 25 TCP SYN packets to SSH (port 22) over 30 seconds.
Confirms reliable detection well above the threshold.

### `bruteforce_below_threshold.pcap`
One source IP sends 9 TCP SYN packets to SSH (port 22) over 30 seconds.
Expected result: zero alerts. Validates the boundary is exclusive below the threshold.

### `bruteforce_cross_service.pcap`
One source IP sends 5 SYN packets to SSH (port 22) and 5 SYN packets to FTP (port 21), same destination, overlapping time window.
Expected result: zero alerts. Validates that attempt counts are tracked per port and not combined across services.

### `bruteforce_outside_window.pcap`
One source IP sends 10 TCP SYN packets to SSH (port 22) spread over 150 seconds.
The maximum count in any 60-second sliding window is 4.
Expected result: zero alerts. Validates the 60-second window boundary.

### `http_flood_threshold.pcap`
One source IP sends 50 HTTP GET requests to port 80 on a single target over 30 seconds.
Validates that the HTTP flood detector fires at the minimum qualifying count within the 30-second window.

### `http_flood_high_volume.pcap`
One source IP sends 100 HTTP GET requests to port 80 over 10 seconds.
Confirms reliable detection well above the threshold.

### `http_flood_below_threshold.pcap`
One source IP sends 49 HTTP GET requests to port 80 over 30 seconds.
Expected result: zero alerts. Validates the boundary is exclusive below the threshold.

### `http_flood_cross_host.pcap`
One source IP sends 25 HTTP GET requests to Host A and 25 to Host B.
Expected result: zero alerts. Validates that attempt counts are tracked per destination host.

### `http_flood_cross_port.pcap`
One source IP sends 25 HTTP GET requests to port 80 and 25 to port 8080 on the same destination host.
Expected result: 1 HTTP Flood alert. Validates that attempt counts are aggregated across ports for the same host.

### `http_flood_outside_window.pcap`
One source IP sends 50 HTTP GET requests to port 80 spread over 120 seconds.
Expected result: zero alerts. Validates the 30-second window boundary.

---

## Known Limitations

- The port scan detector is count-based, not time-based. `port_scan_boundary.pcap` and `port_scan_high_volume.pcap` are functionally equivalent in terms of detection; they differ only in metric values reported.
- The DNS detector counts all DNS-layer packets, regardless of query type or domain. `dns_anomaly` samples reflect total packet volume, not unique domains queried.
- The ICMP detector counts all ICMP packets regardless of type (echo, echo reply, unreachable, etc.).
- The brute force detector uses a sliding window and counts only pure TCP SYN packets (no ACK). It does not detect distributed brute force (multiple source IPs) or attacks on non-standard ports.
- The HTTP flood detector parses application-layer HTTP headers. HTTP/2 and HTTPS are not detected.
