from collections import defaultdict


def detect_smurf_attack(
    packets,
    packet_threshold=10,
    time_window=60
):
    activity = defaultdict(list)

    for packet in packets:

        if packet.get("protocol") != "ICMP":
            continue

        # ICMP Type 8 = Echo Request
        if packet.get("icmp_type") != 8:
            continue

        source_ip = packet.get("src_ip")
        destination_ip = packet.get("dst_ip")
        timestamp = packet.get("timestamp")

        if (
            not source_ip
            or not destination_ip
            or timestamp is None
        ):
            continue

        # Şimdilik /24 broadcast adreslerini kontrol ediyoruz.
        if not destination_ip.endswith(".255"):
            continue

        key = (
            source_ip,
            destination_ip
        )

        activity[key].append(
            float(timestamp)
        )

    alerts = []

    for (
        source_ip,
        destination_ip
    ), timestamps in activity.items():

        timestamps.sort()

        left = 0
        best_count = 0
        best_start = None
        best_end = None

        for right in range(len(timestamps)):

            while (
                timestamps[right]
                - timestamps[left]
                > time_window
            ):
                left += 1

            current_count = (
                right - left + 1
            )

            if current_count > best_count:
                best_count = current_count
                best_start = timestamps[left]
                best_end = timestamps[right]

        if best_count < packet_threshold:
            continue

        alerts.append({
            "type": "SMURF_ATTACK",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "risk_score": 12,

            "first_seen": best_start,
            "last_seen": best_end,
            "packet_count": best_count,

            "reason": (
                f"{time_window} saniye içinde "
                f"{best_count} ICMP Echo Request "
                f"broadcast adresi {destination_ip} "
                "hedefine gönderildi"
            ),

            "evidence": [
                "ICMP Type: 8 (Echo Request)",
                f"Kaynak IP: {source_ip}",
                f"Broadcast hedef: {destination_ip}",
                f"Echo Request sayısı: {best_count}"
            ]
        })

    return alerts