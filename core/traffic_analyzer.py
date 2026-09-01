def analyze_traffic(packets):

    total_packets = len(packets)

    unique_ips = set()
    unique_ports = set()

    tcp_packets = 0
    udp_packets = 0
    icmp_packets = 0

    tcp_connections = set()

    total_bytes = 0

    for packet in packets:

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")

        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")

        protocol = packet.get("protocol")

        packet_size = packet.get("packet_size", 0)

        # IP adreslerini ekle
        if src_ip:
            unique_ips.add(src_ip)

        if dst_ip:
            unique_ips.add(dst_ip)

        # Portları ekle
        if src_port is not None:
            unique_ports.add(src_port)

        if dst_port is not None:
            unique_ports.add(dst_port)

        # Protokol sayıları
        if protocol == "TCP":

            tcp_packets += 1

            if (
                src_ip
                and dst_ip
                and src_port is not None
                and dst_port is not None
            ):

                connection = (
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port
                )

                tcp_connections.add(connection)

        elif protocol == "UDP":

            udp_packets += 1

        elif protocol == "ICMP":

            icmp_packets += 1

        total_bytes += packet_size

    statistics = {
        "total_packets": total_packets,
        "unique_ips": len(unique_ips),
        "unique_ports": len(unique_ports),

        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "icmp_packets": icmp_packets,

        "tcp_connections": len(tcp_connections),

        "total_bytes": total_bytes
    }

    return statistics