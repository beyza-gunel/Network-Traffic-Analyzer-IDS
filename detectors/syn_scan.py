from collections import defaultdict


def _is_pure_syn(
    tcp_flags,
):
    if tcp_flags is None:
        return False

    flags = str(
        tcp_flags
    ).upper()

    return (
        "S" in flags
        and "A" not in flags
    )


def detect_syn_scan(
    packets,
    packet_threshold=10,
    unique_port_threshold=5,
    time_window=10,
):
    """
    Aynı kaynak IP'nin kısa sürede aynı hedefe çok sayıda pure SYN
    gönderip birden fazla hedef portu taramasını SYN Scan olarak tespit eder.

    SYN Flood ile karışmaması için farklı hedef port şartı bulunur.
    """

    activity = defaultdict(list)

    for packet in packets:
        if packet.get("protocol") != "TCP":
            continue

        if not _is_pure_syn(
            packet.get(
                "tcp_flags"
            )
        ):
            continue

        source_ip = packet.get("src_ip")
        destination_ip = packet.get("dst_ip")
        destination_port = packet.get("dst_port")
        timestamp = packet.get("timestamp")

        if (
            not source_ip
            or not destination_ip
            or destination_port is None
            or timestamp is None
        ):
            continue

        try:
            timestamp = float(timestamp)
            destination_port = int(destination_port)
        except (TypeError, ValueError):
            continue

        activity[
            (
                source_ip,
                destination_ip,
            )
        ].append(
            (
                timestamp,
                destination_port,
            )
        )

    alerts = []

    for (
        source_ip,
        destination_ip,
    ), events in activity.items():

        events.sort(
            key=lambda item: item[0]
        )

        left = 0
        best_count = 0
        best_ports = set()
        best_start = None
        best_end = None

        for right in range(
            len(events)
        ):
            while (
                events[right][0]
                - events[left][0]
                > time_window
            ):
                left += 1

            window = events[
                left:right + 1
            ]

            current_count = len(
                window
            )

            current_ports = {
                port
                for (
                    _,
                    port,
                )
                in window
            }

            if (
                current_count > best_count
                or (
                    current_count == best_count
                    and len(current_ports)
                    > len(best_ports)
                )
            ):
                best_count = current_count
                best_ports = current_ports
                best_start = window[0][0]
                best_end = window[-1][0]

        if (
            best_count < packet_threshold
            or len(best_ports)
            < unique_port_threshold
        ):
            continue

        alerts.append(
            {
                "type": "SYN_SCAN",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "risk_score": 10,
                "confidence": 0.92,
                "first_seen": best_start,
                "last_seen": best_end,
                "packet_count": best_count,
                "reason": (
                    f"{time_window} saniye içinde "
                    f"{best_count} SYN paketi ile "
                    f"{len(best_ports)} farklı hedef port tarandı"
                ),
                "evidence": [
                    f"Kaynak IP: {source_ip}",
                    f"Hedef IP: {destination_ip}",
                    f"Pure SYN sayısı: {best_count}",
                    (
                        "Hedef portlar: "
                        + ", ".join(
                            str(port)
                            for port
                            in sorted(
                                best_ports
                            )
                        )
                    ),
                ],
            }
        )

    return alerts
