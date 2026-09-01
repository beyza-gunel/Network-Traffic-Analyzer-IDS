from collections import defaultdict


def detect_port_scan(
    packets,
    port_threshold=10,
    time_window=10
):

    alerts = []

    source_activity = defaultdict(list)

    for packet in packets:

        if packet.get("protocol") != "TCP":
            continue

        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        timestamp = packet.get("timestamp")

        if (
            src_ip is None
            or dst_port is None
            or timestamp is None
        ):
            continue

        source_activity[src_ip].append(
            (timestamp, dst_port)
        )

    for src_ip, activity in source_activity.items():

        activity.sort(key=lambda item: item[0])

        for start_index in range(len(activity)):

            start_time = activity[start_index][0]

            ports = set()

            for current_index in range(
                start_index,
                len(activity)
            ):

                timestamp, port = activity[current_index]

                if timestamp - start_time > time_window:
                    break

                ports.add(port)

            if len(ports) >= port_threshold:

                alerts.append({
                    "type": "PORT_SCAN",
                    "source_ip": src_ip,
                    "risk_score": 5,
                    "reason": (
                        f"{time_window} saniye içinde "
                        f"{len(ports)} farklı TCP portuna erişim"
                    )
                })

                break

    return alerts