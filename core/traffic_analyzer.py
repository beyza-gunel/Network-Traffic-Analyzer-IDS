from collections import Counter


def _endpoint(ip_address, port):
    return (
        str(ip_address),
        (
            int(port)
            if port is not None
            else None
        ),
    )


def _canonical_connection_key(packet):
    """
    Aynı TCP konuşmasının iki yönünü tek bağlantı olarak sayar.

    Örnek:
        192.168.1.10:51000 -> 93.184.216.34:80
        93.184.216.34:80 -> 192.168.1.10:51000

    bu iki yön tek TCP connection kabul edilir.
    """

    if packet.get("protocol") != "TCP":
        return None

    src_ip = packet.get("src_ip")
    dst_ip = packet.get("dst_ip")
    src_port = packet.get("src_port")
    dst_port = packet.get("dst_port")

    if (
        not src_ip
        or not dst_ip
        or src_port is None
        or dst_port is None
    ):
        return None

    source = _endpoint(
        src_ip,
        src_port,
    )

    destination = _endpoint(
        dst_ip,
        dst_port,
    )

    ordered = sorted(
        (
            source,
            destination,
        ),
        key=lambda item: (
            item[0],
            -1
            if item[1] is None
            else item[1],
        ),
    )

    return (
        ordered[0],
        ordered[1],
    )


def analyze_traffic(packets):
    unique_ips = set()
    unique_ports = set()
    tcp_connections = set()

    protocol_distribution = Counter()
    application_distribution = Counter()

    total_bytes = 0

    tcp_packets = 0
    udp_packets = 0
    icmp_packets = 0
    arp_packets = 0
    other_packets = 0

    http_packets = 0
    https_packets = 0
    dns_packets = 0

    for packet in packets:
        total_bytes += int(
            packet.get(
                "packet_size",
                0,
            )
            or 0
        )

        src_ip = packet.get(
            "src_ip"
        )

        dst_ip = packet.get(
            "dst_ip"
        )

        if src_ip:
            unique_ips.add(
                str(src_ip)
            )

        if dst_ip:
            unique_ips.add(
                str(dst_ip)
            )

        src_port = packet.get(
            "src_port"
        )

        dst_port = packet.get(
            "dst_port"
        )

        if src_port is not None:
            try:
                unique_ports.add(
                    int(src_port)
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        if dst_port is not None:
            try:
                unique_ports.add(
                    int(dst_port)
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        protocol = str(
            packet.get(
                "protocol",
                "OTHER",
            )
            or "OTHER"
        ).upper()

        protocol_distribution[
            protocol
        ] += 1

        if protocol == "TCP":
            tcp_packets += 1

            connection_key = (
                _canonical_connection_key(
                    packet
                )
            )

            if connection_key is not None:
                tcp_connections.add(
                    connection_key
                )

        elif protocol == "UDP":
            udp_packets += 1

        elif protocol == "ICMP":
            icmp_packets += 1

        elif protocol == "ARP":
            arp_packets += 1

        else:
            other_packets += 1

        application_protocol = (
            packet.get(
                "application_protocol"
            )
        )

        if application_protocol:
            application_protocol = str(
                application_protocol
            ).upper()

            application_distribution[
                application_protocol
            ] += 1

            if application_protocol == "HTTP":
                http_packets += 1

            elif application_protocol == "HTTPS":
                https_packets += 1

            elif application_protocol == "DNS":
                dns_packets += 1

    return {
        "total_packets": len(
            packets
        ),
        "total_bytes": total_bytes,

        "unique_ips": len(
            unique_ips
        ),
        "unique_ports": len(
            unique_ports
        ),

        "tcp_connections": len(
            tcp_connections
        ),

        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "icmp_packets": icmp_packets,
        "arp_packets": arp_packets,
        "other_packets": other_packets,

        "http_packets": http_packets,
        "https_packets": https_packets,
        "dns_packets": dns_packets,

        "protocol_distribution": dict(
            protocol_distribution
        ),
        "application_distribution": dict(
            application_distribution
        ),
    }
