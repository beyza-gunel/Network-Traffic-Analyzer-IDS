from collections import defaultdict


def detect_syn_scan(
    packets,
    syn_threshold=10,
    unique_port_threshold=5,
    time_window=10
):
    activity = defaultdict(list)

    for packet in packets:

        if packet.get("protocol") != "TCP":
            continue

        if packet.get("tcp_flags") != "S":
            continue

        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        timestamp = packet.get("timestamp")

        if (
            not src_ip
            or dst_port is None
            or timestamp is None
        ):
            continue

        activity[src_ip].append(
            (
                float(timestamp),
                dst_port
            )
        )

    alerts = []

    for source_ip, events in activity.items():

        events.sort(
            key=lambda item: item[0]
        )

        for start_index in range(len(events)):

            ports = set()
            syn_count = 0

            start_time = events[start_index][0]

            for end_index in range(
                start_index,
                len(events)
            ):

                timestamp, destination_port = (
                    events[end_index]
                )

                if (
                    timestamp - start_time
                    > time_window
                ):
                    break

                syn_count += 1
                ports.add(destination_port)

            if (
                syn_count >= syn_threshold
                and
                len(ports) >= unique_port_threshold
            ):

                alerts.append({
                    "type": "SYN_SCAN",

                    "source_ip": source_ip,

                    "risk_score": 7,

                    "reason": (
                        f"{time_window} saniye içinde "
                        f"{syn_count} SYN paketi ile "
                        f"{len(ports)} farklı hedef "
                        f"port tarandı"
                    )
                })

                break

    return alerts