from collections import defaultdict


def detect_icmp_flood(
    packets,
    packet_threshold=20,
    time_window=5
):

    alerts = []

    icmp_activity = defaultdict(list)

    for packet in packets:

        if packet.get("protocol") != "ICMP":
            continue

        src_ip = packet.get("src_ip")
        timestamp = packet.get("timestamp")

        if src_ip is None or timestamp is None:
            continue

        icmp_activity[src_ip].append(timestamp)

    for src_ip, timestamps in icmp_activity.items():

        timestamps.sort()

        for start_index in range(len(timestamps)):

            start_time = timestamps[start_index]

            count = 0

            for current_time in timestamps[start_index:]:

                if current_time - start_time > time_window:
                    break

                count += 1

            if count >= packet_threshold:

                alerts.append({
                    "type": "ICMP_FLOOD",
                    "source_ip": src_ip,
                    "risk_score": 10,
                    "reason": (
                        f"{time_window} saniye içinde "
                        f"{count} ICMP paketi gönderildi"
                    )
                })

                break

    return alerts