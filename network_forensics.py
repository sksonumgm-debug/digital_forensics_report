from collections import Counter
from datetime import datetime, timezone
import ipaddress
import os


MAX_PACKETS = 1_000_000
MAX_TRACKED_FLOWS = 20_000
MAX_FINDINGS = 5_000
COMMON_PORTS = {
    20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 161, 389, 443, 445,
    465, 587, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443,
}


class PacketCaptureError(Exception):
    pass


def analyze_pcap(path):
    try:
        from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP, PcapReader
    except ImportError as exc:
        raise PacketCaptureError(
            "PCAP analysis requires Scapy. Install the project dependencies and retry."
        ) from exc

    if not os.path.isfile(path):
        raise PacketCaptureError("The uploaded packet capture is missing.")

    flows = {}
    dns_queries = Counter()
    traffic_windows = Counter()
    packet_count = 0
    untracked_flow_packets = 0
    packet_limit_reached = False
    total_bytes = 0
    first_timestamp = None
    last_timestamp = None
    try:
        with open(path, "rb") as packet_file:
            capture = PcapReader(packet_file)
            for packet in capture:
                packet_count += 1
                if packet_count > MAX_PACKETS:
                    packet_count -= 1
                    packet_limit_reached = True
                    break
                total_bytes += len(packet)
                try:
                    observed = float(packet.time)
                except (AttributeError, TypeError, ValueError, OverflowError):
                    observed = None
                if observed is not None:
                    first_timestamp = observed if first_timestamp is None else min(first_timestamp, observed)
                    last_timestamp = observed if last_timestamp is None else max(last_timestamp, observed)

                if IP in packet:
                    source = packet[IP].src
                    destination = packet[IP].dst
                elif IPv6 in packet:
                    source = packet[IPv6].src
                    destination = packet[IPv6].dst
                else:
                    continue

                try:
                    ipaddress.ip_address(source)
                    ipaddress.ip_address(destination)
                except ValueError:
                    continue

                protocol = "other"
                source_port = 0
                destination_port = 0
                syn_attempt = False
                if TCP in packet:
                    protocol = "tcp"
                    source_port = int(packet[TCP].sport)
                    destination_port = int(packet[TCP].dport)
                    flags = int(packet[TCP].flags)
                    syn_attempt = bool(flags & 0x02) and not bool(flags & 0x10)
                elif UDP in packet:
                    protocol = "udp"
                    source_port = int(packet[UDP].sport)
                    destination_port = int(packet[UDP].dport)

                if observed is not None:
                    traffic_windows[(source, destination, int(observed // 60))] += len(packet)

                key = (source, destination, protocol, source_port, destination_port)
                flow = flows.get(key)
                if flow is None and len(flows) >= MAX_TRACKED_FLOWS:
                    untracked_flow_packets += 1
                else:
                    if flow is None:
                        flow = {
                            "source_ip": source,
                            "destination_ip": destination,
                            "protocol": protocol,
                            "source_port": source_port,
                            "destination_port": destination_port,
                            "packets": 0,
                            "bytes": 0,
                            "syn_attempts": 0,
                            "first_seen_epoch": observed,
                            "last_seen_epoch": observed,
                        }
                        flows[key] = flow
                    flow["packets"] += 1
                    flow["bytes"] += len(packet)
                    flow["syn_attempts"] += int(syn_attempt)
                    if observed is not None:
                        flow["first_seen_epoch"] = (
                            observed if flow["first_seen_epoch"] is None
                            else min(flow["first_seen_epoch"], observed)
                        )
                        flow["last_seen_epoch"] = (
                            observed if flow["last_seen_epoch"] is None
                            else max(flow["last_seen_epoch"], observed)
                        )

                if DNS in packet and packet[DNS].qr == 0 and DNSQR in packet:
                    dns = packet[DNS]
                    questions = dns.qd if isinstance(dns.qd, list) else [dns.qd]
                    for question in questions:
                        if question is None:
                            continue
                        name = question.qname.decode("utf-8", errors="replace").rstrip(".").lower()
                        if name:
                            dns_queries[(source, name, int(question.qtype))] += 1
    except (OSError, EOFError, ValueError) as exc:
        raise PacketCaptureError(f"Could not read the packet capture: {exc}") from exc
    except Exception as exc:
        raise PacketCaptureError(f"Packet capture parsing failed: {exc}") from exc

    if packet_count == 0:
        raise PacketCaptureError("The packet capture contains no readable packets.")

    flow_rows = []
    events = []
    window_values = sorted(traffic_windows.values())
    median_window_bytes = window_values[len(window_values) // 2] if window_values else 0
    spike_windows = {
        key for key, byte_count in traffic_windows.items()
        if byte_count >= 1_000_000 and byte_count > max(1_000_000, median_window_bytes * 5)
    }
    spike_pairs = {(source, destination) for source, destination, _ in spike_windows}
    for flow in sorted(flows.values(), key=lambda item: item["bytes"], reverse=True)[:MAX_FINDINGS]:
        first_seen = _iso_timestamp(flow.pop("first_seen_epoch"))
        last_seen = _iso_timestamp(flow.pop("last_seen_epoch"))
        destination_port = flow["destination_port"]
        service_uncommon = bool(destination_port and destination_port not in COMMON_PORTS)
        repeated_attempts = flow["syn_attempts"] >= 10
        traffic_spike = (flow["source_ip"], flow["destination_ip"]) in spike_pairs
        severity = "high" if repeated_attempts else "medium" if traffic_spike else "low" if service_uncommon else "info"
        reasons = []
        if repeated_attempts:
            reasons.append(f"{flow['syn_attempts']} TCP SYN attempts were observed in this aggregated flow.")
        if service_uncommon:
            reasons.append(f"Destination port {destination_port} is outside the configured common-service list; this is not inherently malicious.")
        if traffic_spike:
            reasons.append(
                "This source/destination pair exceeded five times the capture's median "
                "60-second traffic window and records at least 1 MB."
            )
        description = (
            f"{flow['protocol'].upper()} {flow['source_ip']}:{flow['source_port']} → "
            f"{flow['destination_ip']}:{destination_port} ({flow['packets']} packets, {flow['bytes']:,} bytes)"
        )
        events.append({
            "timestamp": first_seen,
            "severity": severity,
            "event_type": "network_flow",
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],
            "destination_port": destination_port,
            "summary": description,
            "details": {
                **flow,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "uncommon_port": service_uncommon,
                "traffic_spike": traffic_spike,
                "reasons": reasons or ["Observed flow summary; no configured network heuristic matched."],
            },
        })
        flow_rows.append({
            **flow, "first_seen": first_seen, "last_seen": last_seen,
            "severity": severity,
        })

    for (source, destination, minute), byte_count in list(spike_windows)[:MAX_FINDINGS]:
        timestamp = _iso_timestamp(minute * 60)
        events.append({
            "timestamp": timestamp,
            "severity": "high" if byte_count >= 10_000_000 else "medium",
            "event_type": "traffic_volume_spike",
            "source_ip": source,
            "destination_ip": destination,
            "destination_port": None,
            "summary": (
                f"Traffic volume spike: {byte_count:,} bytes from {source} to {destination} "
                "within a 60-second window"
            ),
            "details": {
                "window_start": timestamp,
                "window_seconds": 60,
                "bytes": byte_count,
                "capture_median_window_bytes": median_window_bytes,
                "reasons": [
                    "At least 1 MB was observed in this 60-second source/destination window "
                    "and its volume exceeded five times the capture median."
                ],
            },
        })

    for (source, domain, query_type), count in list(
        sorted(dns_queries.items(), key=lambda entry: entry[1], reverse=True)
    )[:MAX_FINDINGS]:
        events.append({
            "timestamp": None,
            "severity": "info",
            "event_type": "dns_query",
            "source_ip": source,
            "destination_ip": "",
            "destination_port": 53,
            "summary": f"DNS query for {domain} ({count} request{'s' if count != 1 else ''})",
            "details": {
                "domain": domain,
                "query_type": query_type,
                "query_count": count,
                "reasons": ["DNS query observed in the uploaded packet capture; reputation was not checked."],
            },
        })

    events.sort(key=lambda event: event.get("timestamp") or "")
    summary = {
        "packet_count": packet_count,
        "packet_limit_reached": packet_limit_reached,
        "total_bytes": total_bytes,
        "unique_flows": len(flows),
        "untracked_flow_packets": untracked_flow_packets,
        "findings_truncated": len(flows) > MAX_FINDINGS or len(spike_windows) > MAX_FINDINGS or len(dns_queries) > MAX_FINDINGS,
        "unique_dns_queries": len(dns_queries),
        "first_seen": _iso_timestamp(first_timestamp),
        "last_seen": _iso_timestamp(last_timestamp),
        "flows": sorted(flow_rows, key=lambda flow: flow["bytes"], reverse=True)[:500],
        "dns": [
            {"source_ip": source, "domain": domain, "query_type": query_type, "count": count}
            for (source, domain, query_type), count in sorted(
                dns_queries.items(), key=lambda entry: entry[1], reverse=True
            )[:500]
        ],
    }
    return packet_count, summary, events


def _iso_timestamp(value):
    if value is None:
        return None
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")
