from collections import Counter

from models.flow import FlowRecord


SUPPORTED_FLOW_PROTOCOLS = {
    "TCP",
    "UDP",
    "ICMP",
}


def _endpoint(
    ip_address,
    port,
):
    return (
        str(
            ip_address
        ),
        (
            int(port)
            if port is not None
            else None
        ),
    )


def _canonical_flow_key(
    packet,
):
    protocol = str(
        packet.get(
            "protocol",
            "",
        )
        or ""
    ).upper()

    if protocol not in SUPPORTED_FLOW_PROTOCOLS:
        return None

    src_ip = packet.get(
        "src_ip"
    )
    dst_ip = packet.get(
        "dst_ip"
    )

    if not src_ip or not dst_ip:
        return None

    src_port = packet.get(
        "src_port"
    )
    dst_port = packet.get(
        "dst_port"
    )

    source = _endpoint(
        src_ip,
        src_port,
    )
    destination = _endpoint(
        dst_ip,
        dst_port,
    )

    # Aynı TCP/UDP konuşmasının iki yönünü
    # tek flow altında topluyoruz.
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
        protocol,
        ordered[0],
        ordered[1],
    )


def analyze_flows(
    packets,
):
    flows = {}
    app_counters = {}
    flag_sets = {}

    for packet in packets:
        key = _canonical_flow_key(
            packet
        )

        if key is None:
            continue

        protocol = str(
            packet.get(
                "protocol",
                "",
            )
            or ""
        ).upper()

        src_ip = packet.get(
            "src_ip"
        )
        dst_ip = packet.get(
            "dst_ip"
        )
        src_port = packet.get(
            "src_port"
        )
        dst_port = packet.get(
            "dst_port"
        )

        timestamp = packet.get(
            "timestamp"
        )

        if timestamp is None:
            continue

        try:
            timestamp = float(
                timestamp
            )
        except (
            TypeError,
            ValueError,
        ):
            continue

        packet_size = int(
            packet.get(
                "packet_size",
                0,
            )
            or 0
        )

        if key not in flows:
            flows[key] = FlowRecord(
                protocol=protocol,
                source_ip=str(
                    src_ip
                ),
                destination_ip=str(
                    dst_ip
                ),
                source_port=(
                    int(src_port)
                    if src_port is not None
                    else None
                ),
                destination_port=(
                    int(dst_port)
                    if dst_port is not None
                    else None
                ),
                first_seen=timestamp,
                last_seen=timestamp,
            )

            app_counters[
                key
            ] = Counter()

            flag_sets[
                key
            ] = set()

        flow = flows[
            key
        ]

        flow.packet_count += 1
        flow.byte_count += (
            packet_size
        )

        flow.first_seen = min(
            flow.first_seen,
            timestamp,
        )
        flow.last_seen = max(
            flow.last_seen,
            timestamp,
        )

        same_direction = (
            str(src_ip)
            == flow.source_ip
            and str(dst_ip)
            == flow.destination_ip
            and (
                src_port
                == flow.source_port
            )
            and (
                dst_port
                == flow.destination_port
            )
        )

        if same_direction:
            flow.forward_packets += 1
        else:
            flow.reverse_packets += 1

        application_protocol = (
            packet.get(
                "application_protocol"
            )
        )

        if application_protocol:
            app_counters[
                key
            ][
                str(
                    application_protocol
                )
            ] += 1

        tcp_flags = packet.get(
            "tcp_flags"
        )

        if tcp_flags:
            flag_sets[
                key
            ].add(
                str(
                    tcp_flags
                )
            )

    results = []

    for key, flow in flows.items():
        if app_counters[
            key
        ]:
            flow.application_protocol = (
                app_counters[
                    key
                ].most_common(
                    1
                )[0][0]
            )

        flow.tcp_flags = sorted(
            flag_sets[
                key
            ]
        )

        results.append(
            flow
        )

    results.sort(
        key=lambda flow: (
            flow.packet_count,
            flow.byte_count,
        ),
        reverse=True,
    )

    return results
