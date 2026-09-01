from collections import defaultdict


def detect_syn_scan(
    packets,
    syn_threshold=10,
    time_window=10
):

    alerts = []

    syn_activity = defaultdict(list)

    for packet in packets:

        if packet.get("protocol") != "TCP":
            continue

        flags = packet.get("tcp_flags")

        if flags != "S":
            continue

        src_ip = packet.get("src_ip")
        timestamp = packet.get("timestamp")

        if src_ip is None or timestamp is None:
            continue

        syn_activity[src_ip].append(timestamp)

    for src_ip, timestamps in syn_activity.items():

        timestamps.sort()

        for start_index in range(len(timestamps)):

            start_time = timestamps[start_index]

            count = 0

            for current_time in timestamps[start_index:]:

                if current_time - start_time > time_window:
                    break

                count += 1

            if count >= syn_threshold:

                alerts.append({
                    "type": "SYN_SCAN",
                    "source_ip": src_ip,
                    "risk_score": 7,
                    "reason": (
                        f"{time_window} saniye içinde "
                        f"{count} SYN paketi gönderildi"
                    )
                })

                break

    return alerts