from collections import defaultdict


def detect_port_scan(
    packets,
    unique_port_threshold=10,
    time_window=10,
):
    """
    Aynı kaynak IP'nin kısa sürede aynı hedef IP üzerinde çok sayıda
    farklı TCP hedef portuna erişmesini Port Scan olarak işaretler.
    """

    activity = defaultdict(list)

    for packet in packets:
        if packet.get("protocol") != "TCP":
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

            current_ports = {
                port
                for (
                    _,
                    port,
                )
                in events[
                    left:right + 1
                ]
            }

            if len(current_ports) > len(
                best_ports
            ):
                best_ports = current_ports
                best_start = events[
                    left
                ][0]
                best_end = events[
                    right
                ][0]

        if len(best_ports) < unique_port_threshold:
            continue

        alerts.append(
            {
                "type": "PORT_SCAN",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "risk_score": 10,
                "confidence": 0.90,
                "first_seen": best_start,
                "last_seen": best_end,
                "packet_count": len(
                    best_ports
                ),
                "reason": (
                    f"{time_window} saniye içinde "
                    f"{len(best_ports)} farklı TCP portuna erişim"
                ),
                "evidence": [
                    f"Kaynak IP: {source_ip}",
                    f"Hedef IP: {destination_ip}",
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
                    (
                        f"Farklı hedef port sayısı: "
                        f"{len(best_ports)}"
                    ),
                ],
            }
        )

    return alerts
